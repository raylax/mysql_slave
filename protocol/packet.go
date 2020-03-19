package protocol

type ResponsePacket struct {
	header       int
	errorCode    int
	errorMessage string
}

func (s *ResponsePacket) Ok() bool {
	return isOkResponsePacket(s.header)
}

func (s *ResponsePacket) ErrorCode() int {
	return s.errorCode
}

func (s *ResponsePacket) ErrorMessage() string {
	return s.errorMessage
}

func ParseResponsePacket(data []byte) *ResponsePacket {
	var r = &ResponsePacket{}
	var offset int
	r.header = readInt(data[offset : offset+1])
	offset += 1
	if isOkResponsePacket(r.header) {
		return r
	}
	r.errorCode = readInt(data[offset : offset+2])
	offset += 2
	// skip 6 bytes
	offset += 6
	r.errorMessage = readString(data[offset:])
	return r
}

func isOkResponsePacket(h int) bool {
	return h == 0x00 || h == 0xfe
}

type HeaderPacket struct {
	// 3
	PayloadLength int8
	// 1
	SequenceId int8
}

type HandshakePacket struct {
	// 1
	ProtocolVersion int8
	// nul
	ServerVersion string
	// 4
	ConnectionId int8
	// 8
	AuthPluginDataPart1 string
	// 1
	Filler int8
	// 2
	CapabilityFlagsLower int8
}
