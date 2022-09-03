package app

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/lfaoro/trailblaze/pkg"
	"github.com/lfaoro/trailblaze/pkg/scan"
)

var (
	scanLocalFlag   string
	scanRangeFlag   string
	scanPortsFlag   string
	scanLanFlag     bool
	scanThreadsFlag int
	scanTimeoutFlag time.Duration
	scanOutputFlag  string
)

// TODO: add all ports syntax: 1-65535 or all

var scanCmd = &cli.Command{
	Name:    "scan",
	Usage:   "scan --lan --threads 5000",
	Aliases: []string{"s"},
	Action:  scanAction,

	Flags: []cli.Flag{

		// TODO: Not implemented
		&cli.StringFlag{
			Name:      "file",
			Aliases:   []string{"f"},
			Usage:     "provide a `FILE` containing an IP list to scan",
			TakesFile: true,
			Hidden:    true,
		},

		&cli.StringFlag{
			Name:        "range",
			Aliases:     []string{"r"},
			Usage:       "scan wildcard(*,-)",
			DefaultText: "--range '11.1-200.*.*'",
			Destination: &scanRangeFlag,
		},

		&cli.StringFlag{
			Name:        "local",
			Aliases:     []string{"L"},
			Usage:       "scan all private (--local all), bogon (--local extra) ranges (10/172/192/all/extra)",
			DefaultText: "--local 192",
			Destination: &scanLocalFlag,
		},

		&cli.BoolFlag{
			Name:        "lan",
			Aliases:     []string{"l"},
			Usage:       "scan every network configured on this server (ip routes)",
			Destination: &scanLanFlag,
		},

		&cli.StringFlag{
			Name:        "ports",
			Aliases:     []string{"p"},
			Usage:       "TCP connect to these ports `PORT1,PORT2,PORTn`",
			Value:       "22",
			Destination: &scanPortsFlag,
		},

		&cli.IntFlag{
			Name:        "threads",
			Aliases:     []string{"j"},
			Usage:       "max concurrent threads to spawn (check your system limits ulimit -n)",
			Value:       1024,
			Destination: &scanThreadsFlag,
		},

		&cli.DurationFlag{
			Name:        "timeout",
			Aliases:     []string{"t"},
			Usage:       "timeout for TCP connections",
			Value:       time.Second * 5,
			Destination: &scanTimeoutFlag,
		},

		&cli.StringFlag{
			Name:        "output",
			Aliases:     []string{"o"},
			Usage:       "write found banners to `FILE` in IP:PORT:BANNER format",
			Destination: &scanOutputFlag,

			Value: "scan.log",
		},
	},
}

func scanAction(c *cli.Context) error {
	var hosts []string

	if scanRangeFlag != "" {
		log.Infof("generating addresses for %v ...", scanRangeFlag)
		ss, err := IPv4Wildcard(scanRangeFlag)
		if err != nil {
			return err
		}
		hosts = ss
		log.Infof("created %v addresses", len(hosts))
	}

	if scanLocalFlag != "" {
		log.Infof("generating addresses for %v ...", scanLocalFlag)
		hosts = genRanges(scanLocalFlag)
		log.Infof("created %v addresses", len(hosts))
	}

	if scanLanFlag {
		hostname, _ := os.Hostname()
		log.Infof("gathering local networks from %v ...", hostname)
		addrs, err := scanLan()
		if err != nil {
			return err
		}
		hosts = append(hosts, addrs...)
	}

	log.Info("randomizing hosts...")
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(hosts), func(i, j int) { hosts[i], hosts[j] = hosts[j], hosts[i] })

	s := scan.NewScanner(scanOutputFlag)
	defer s.Close()

	var ports []string
	ports = strings.Split(scanPortsFlag, ",")

	log.Infof("starting scan using %v threads", scanThreadsFlag)
	estimate := len(hosts) * len(ports)
	bar := pkg.NewProgressBar(estimate, "Scanning...")

	var syncC = make(chan struct{}, scanThreadsFlag)
	wg := &sync.WaitGroup{}
	for _, host := range hosts {
		for _, port := range ports {
			if i, _ := strconv.Atoi(port); i > 65536 {
				log.Errorf("invalid port %v", i)
				continue
			}

			syncC <- struct{}{}
			wg.Add(1)
			scan := fmt.Sprintf("%v:%v", host, port)
			go func(scan string) {
				defer func() {
					bar.Add(1)
					wg.Done()
					<-syncC
				}()

				err := tcpDial(scan, scanTimeoutFlag)
				if err != nil {
					s.AddFailReason(err)
					log.Debug(err)
				} else {
					s.AddOpenPort()
					desc := fmt.Sprintf("OPEN[%v] %v", s.OpenPorts(), scan)
					bar.Describe(desc)
					s.Save(scan)
				}
			}(scan)
		}
	}
	wg.Wait()

	desc := fmt.Sprintf("OPEN[%v]", s.OpenPorts())
	bar.Describe(desc)
	bar.Finish()

	fmt.Printf("\n")
	s.PrintStats()
	fmt.Printf("$ tail scan.log\n")

	return nil
}

func IPv4Wildcard(target string) ([]string, error) {
	var hosts []string

	items := strings.Split(target, ".")
	var blocks [4][]string
	for i := 0; i <= 3; i++ {
		var block []string
		item := items[i]
		if item == "*" {
			for j := 1; j < 255; j++ {
				block = append(block, strconv.Itoa(j))
			}
		} else if strings.ContainsAny(item, "-") {
			a := strings.Split(item, "-")
			Start, err := strconv.Atoi(a[0])
			if err != nil {
				return nil, err
			}
			End, err := strconv.Atoi(a[1])
			if err != nil {
				return nil, err
			}
			if Start >= End {
				return nil, err
			}
			for j := Start; j <= End; j++ {
				block = append(block, strconv.Itoa(j))
			}
		} else {
			j, err := strconv.Atoi(item)
			if err != nil {
				return nil, err
			}
			block = append(block, strconv.Itoa(j))
		}
		blocks[i] = block
	}
	for _, a1 := range blocks[0] {
		for _, a2 := range blocks[1] {
			for _, a3 := range blocks[2] {
				for _, a4 := range blocks[3] {
					items := [4]string{a1, a2, a3, a4}
					ip := strings.Join(items[:], ".")
					hosts = append(hosts, ip)
				}
			}
		}
	}
	return hosts, nil
}

// TODO: add more bogon networks
// doc: www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
func genRanges(s string) []string {
	var hosts []string

	switch s {
	case "all":
		h, err := IPv4Wildcard("10.*.*.*")
		hosts = append(hosts, h...)

		h, err = IPv4Wildcard("172.16-31.*.*")
		hosts = append(hosts, h...)

		h, err = IPv4Wildcard("192.168.*.*")
		hosts = append(hosts, h...)

		if err != nil {
			log.Fatal(err)
		}

	case "extra":
		h, err := IPv4CIDR("100.64.0.0/10")
		hosts = append(hosts, h...)

		h, err = IPv4CIDR("192.0.0.0/24")
		hosts = append(hosts, h...)

		if err != nil {
			log.Fatal(err)
		}

	case "10":
		h, err := IPv4Wildcard("10.*.*.*")
		hosts = append(hosts, h...)
		if err != nil {
			log.Fatal(err)
		}

	case "172":
		h, err := IPv4Wildcard("172.16-31.*.*")
		hosts = append(hosts, h...)
		if err != nil {
			log.Fatal(err)
		}

	case "192":
		h, err := IPv4Wildcard("192.168.*.*")
		hosts = append(hosts, h...)
		if err != nil {
			log.Fatal(err)
		}
	}
	return hosts
}

func tcpDial(host string, timeout time.Duration) error {
	var retry int
RETRY:
	conn, err := net.DialTimeout("tcp", host, timeout)
	if err != nil {
		if retry < 1 {
			timeout += timeout
			retry++
			goto RETRY
		}
		return err
	}
	conn.Close()
	return nil
}

func IPv4CIDR(cidr string) ([]string, error) {
	inc := func(ip net.IP) {
		for i := len(ip) - 1; i >= 0; i-- {
			ip[i]++
			if ip[i] > 0 {
				break
			}
		}
	}
	var hosts []string
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		hosts = append(hosts, ip.String())
	}
	size := len(hosts)

	if size > 2 {
		hosts = hosts[1 : size-1]
	}
	return hosts, nil
}

func scanLan() ([]string, error) {
	var hosts []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if strings.Contains(addr.String(), ":") ||
			strings.Contains(addr.String(), "127.0.0.1") {
			continue
		}
		cidr, err := IPv4CIDR(addr.String())
		if err != nil {
			log.Error(err)
			continue
		}
		hosts = append(hosts, cidr...)
	}
	return hosts, nil
}
