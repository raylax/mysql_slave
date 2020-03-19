package main

import (
	"github.com/raylax/mysql_slave/client"
	log "github.com/sirupsen/logrus"
)

func main() {
	var slave = client.NewSlave("127.0.0.1", 3306, "slave", "slave")
	err := slave.Connect()
	if err != nil {
		log.Error(err)
	}
}
