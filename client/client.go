package client

import (
	"github.com/raylax/mysql_slave/protocol"
	log "github.com/sirupsen/logrus"
	"net"
	"strconv"
)

type Slave struct {
	host     string
	port     int
	username string
	password string
}

func NewSlave(host string, port int, username string, password string) *Slave {
	return &Slave{
		host:     host,
		port:     port,
		username: username,
		password: password,
	}
}

func (s *Slave) Connect() error {
	addr, err := net.ResolveTCPAddr("tcp", s.host+":"+strconv.Itoa(s.port))
	if err != nil {
		return err
	}
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Infof("%s -> %s, connected", conn.LocalAddr().String(), conn.RemoteAddr().String())
	return processConnection(conn, s.username, s.password)
}

func processConnection(conn *net.TCPConn, username string, password string) error {
	err := protocol.Handshake(conn, username, password)
	if err != nil {
		return err
	}
	return nil
}
