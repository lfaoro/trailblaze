package banner

import (
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// retryConn retries a TCP connection by growing its timeout.
func retryConn(hostPort string, timeout time.Duration) (net.Conn, error) {
	_timeout := timeout
	for i := 0; i < 2; i++ {
		conn, err := net.DialTimeout("tcp", hostPort, timeout)
		if err != nil {
			timeout += _timeout
			log.Debugf("growing timeout %v", timeout)
			continue
		}
		return conn, nil
	}
	return nil, fmt.Errorf("tcp conn timeout")
}

func Extract(hostPort string, timeout time.Duration) (string, error) {
	conn, err := retryConn(hostPort, timeout)
	if err != nil {
		return "", fmt.Errorf("ssh: dial: %v", err)
	}
	defer conn.Close()

	go func(conn net.Conn) {
		<-time.After(timeout * 3)
		log.Debugf("%v closing conn", hostPort)
		conn.Close()
	}(conn)

	log.Debugf("connected: [%v] --> [%v]\n", conn.LocalAddr().String(), conn.RemoteAddr().String())
	conn.SetDeadline(time.Now().Add(time.Second * 15))

	// we submit this version string
	var ssh_version = []byte("SSH-2.0-OpenSSH\r\n")
	if _, err := conn.Write(ssh_version); err != nil {
		return "", fmt.Errorf("ssh: conn write: %v", err)
	}

	them, err := readVersion(conn)
	if err != nil {
		return "", fmt.Errorf("ssh: read version: %v", err)
	}

	return string(them), nil
}
