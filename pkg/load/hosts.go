package load

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type Host struct {
	IP   string
	Port int
}

func (h Host) String() string {
	return fmt.Sprintf("%v:%v", h.IP, h.Port)
}

func Hosts(file string) []Host {
	var hosts []Host

	f, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	scan := bufio.NewScanner(f)
	for scan.Scan() {
		if scan.Err() != nil {
			log.Error(scan.Err())
		}

		if !strings.Contains(scan.Text(), ":") {
			log.Errorf("%v:%v wrong format, use USER:PASS", file, scan.Text())
			continue
		}
		if strings.HasPrefix(scan.Text(), "#") {
			continue
		}

		host := strings.TrimSpace(scan.Text())
		split := strings.Split(host, ":")
		if len(split) < 2 {
			log.Errorf("[%v] wrong format, use IP:PORT", host)
			continue
		}

		ip := split[0]
		port := split[1]
		port = strings.Split(port, " ")[0]
		_port, err := strconv.Atoi(port)
		if err != nil {
			log.Error(err)
		}

		h := Host{
			IP:   ip,
			Port: _port,
		}
		hosts = append(hosts, h)
	}
	return hosts
}
