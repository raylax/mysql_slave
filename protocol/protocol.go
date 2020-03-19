package protocol

import (
	"bufio"
	"crypto/sha1"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
)

const (
	packetHeaderLen        = 4
	protocolVersionLen     = 1
	connectionIdLen        = 4
	authPluginDataPart1Len = 8
	capabilityFlagsLen     = 2
	statusFlagsLen         = 2
	authPluginDataLenLen   = 1
	reservedLen            = 10
	// Charset
	CharsetUTF8 = 33
	// Auth plugin
	authPluginNameNative = "mysql_native_password"
	// Flags
	// see https://dev.mysql.com/doc/internals/en/capability-flags.html#packet-Protocol::CapabilityFlags
	clientLongPassword     = 0x00000001
	clientPluginAuth       = 0x00080000
	clientSecureConnection = 0x00008000
	clientProtocol41       = 0x00000200
)

func Handshake(conn *net.TCPConn, username string, password string) error {
	log.Infof("start handshake")
	reader := bufio.NewReader(conn)
	payloadLength, _, err := readHeader(reader)
	if err != nil {
		return err
	}
	payload, err := readPayload(reader, payloadLength)
	if err != nil {
		return err
	}
	var offset int
	// see https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeV10
	protocolVersion := readInt(payload[offset : offset+protocolVersionLen])
	if protocolVersion != 10 {
		return newError("supported handshake version `%d` only", protocolVersion)
	}
	offset += protocolVersionLen
	serverVersion, serverVersionLen := readStringNul(payload[offset:])
	offset += serverVersionLen
	connectionId := readInt(payload[offset : offset+connectionIdLen])
	offset += connectionIdLen
	log.Infof("protocol:%d server:%s session:%d", protocolVersion, serverVersion, connectionId)
	authPluginDataPart1 := readString(payload[offset : offset+authPluginDataPart1Len])
	offset += authPluginDataPart1Len
	// skip `filler`
	offset += 1
	capabilityFlags := readInt(payload[offset : offset+capabilityFlagsLen])
	offset += capabilityFlagsLen
	// skip `character set`
	offset += 1
	// skip `status flags set`
	offset += statusFlagsLen
	capabilityFlags = (readInt(payload[offset:offset+capabilityFlagsLen]) << 16) | capabilityFlags
	offset += capabilityFlagsLen
	var authPluginDataLen int
	if capabilityFlags&clientPluginAuth > 0 {
		authPluginDataLen = readInt(payload[offset : offset+authPluginDataLenLen])
		offset += authPluginDataLenLen
	} else {
		// skip 1byte
		offset += 1
	}
	// skip `reserved` 10bytes
	offset += reservedLen
	if capabilityFlags&clientSecureConnection == 0 {
		return newError("supported auth plugin `%s` only", authPluginNameNative)
	}
	part2Len := 13
	if authPluginDataLen-8 > part2Len {
		part2Len = authPluginDataLen - 8
	}
	authPluginDataPart2 := readString(payload[offset : offset+part2Len])
	offset += part2Len
	if capabilityFlags&clientPluginAuth == 0 {
		return newError("supported auth plugin `%s` only", authPluginNameNative)
	}
	authPluginName, authPluginNameLen := readStringNul(payload[offset:])
	offset += authPluginNameLen
	if authPluginName != authPluginNameNative {
		return newError("supported auth plugin `%s` only", authPluginNameNative)
	}

	// see https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse41
	// capabilityFlags
	var response = make([]byte, 0, 0xff)
	// capability flags `CLIENT_PROTOCOL_41`
	response = writeInt(response, clientProtocol41|clientLongPassword|clientSecureConnection|clientPluginAuth, 4)
	// max-packet size `65535`
	response = writeInt(response, 0xffff, 4)
	// character set `utf8`
	response = writeInt(response, CharsetUTF8, 1)
	// reserved (all [0])
	response = writeInt(response, 0x00, 23)
	// username
	response = writeStringNul(response, username)
	// SHA1( password ) XOR SHA1( "20-bytes random data from server" <concat> SHA1( SHA1( password ) ) )
	passwordSha1 := sha1.Sum([]byte(password))
	randomData := append([]byte(authPluginDataPart1), authPluginDataPart2...)[0:20]
	authResponse := xor(passwordSha1, sha1.Sum(concatArray(randomData, sha1.Sum(passwordSha1[:]))))
	// length of auth-response
	response = writeInt(response, len(authResponse), 1)
	// auth-response
	response = writeString(response, string(authResponse))
	// auth plugin name
	response = writeStringNul(response, authPluginNameNative)

	// Response header
	header := make([]byte, 0, 4)
	// PayloadLength 3
	header = writeInt(header, len(response), 3)
	// SequenceId 1
	header = writeInt(header, 0x01, 1)

	// send to server
	writer := bufio.NewWriter(conn)
	_, err = writer.Write(append(header, response...))
	if err != nil {
		return err
	}
	err = writer.Flush()
	if err != nil {
		return err
	}

	packetLen, _, err := readHeader(reader)
	payload, err = readPayload(reader, packetLen)
	if err != nil {
		return err
	}
	responsePacket := ParseResponsePacket(payload)
	if !responsePacket.Ok() {
		return newError("handshake error, code:%d message:%s", responsePacket.errorCode, responsePacket.errorMessage)
	}
	log.Info("handshake complete")
	return nil
}

func xor(a [20]byte, b [20]byte) []byte {
	data := make([]byte, 20)
	for i := range a {
		data[i] = a[i] ^ b[i]
	}
	return data
}

func concatArray(data []byte, a [20]byte) []byte {
	for i := range a {
		data = append(data, a[i])
	}
	return data
}

func writeString(data []byte, str string) []byte {
	data = append(data, []byte(str)...)
	return data
}

func writeStringNul(data []byte, str string) []byte {
	data = append(writeString(data, str), 0x00)
	return data
}

func writeInt(data []byte, n int, len int) []byte {
	for i := 0; i < len; i++ {
		data = append(data, byte(n>>(i*8)&0xff))
	}
	return data
}

func readHeader(reader *bufio.Reader) (int, int, error) {
	header, err := readData(reader, packetHeaderLen)
	if err != nil {
		return 0, 0, err
	}
	return readInt(header[:3]), readInt(header[3:]), nil
}

func readPayload(reader *bufio.Reader, payloadLen int) ([]byte, error) {
	return readData(reader, payloadLen)
}

func readData(reader *bufio.Reader, len int) ([]byte, error) {
	data := make([]byte, len)
	n, err := reader.Read(data)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, newError("data length != %d", len)
	}
	return data, nil
}

func readString(data []byte) string {
	return string(data)
}

func readStringNul(data []byte) (string, int) {
	var p int
	for i, b := range data {
		if b == 0x00 {
			p = i
			break
		}
	}
	return string(data[:p]), p + 1
}

func readInt(data []byte) int {
	var r int
	for i := 0; i < len(data); i++ {
		r |= int(data[i]) << (i * 8)
	}
	return r
}

func newError(message string, args ...interface{}) error {
	return errors.New(fmt.Sprintf(message, args...))
}
