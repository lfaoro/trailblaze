package app

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/lfaoro/trailblaze/pkg"
	"github.com/lfaoro/trailblaze/pkg/banner"
	"github.com/lfaoro/trailblaze/pkg/load"
	"github.com/lfaoro/trailblaze/pkg/rlimit"
)

var (
	flagBannerThreads    int
	flagBannerTimeout    time.Duration
	flagBannerHostsFile  string
	flagBannerOutputFile string

	bannerThreadsC chan struct{}
)

var bannerCmd = &cli.Command{
	Name:    "banner",
	Aliases: []string{"b"},

	Usage:       "grab SSH version (banner) without performing a login",
	Description: "banner extracts SSH versions from RFC4253 compliant TCP connections before reaching the login step in the protocol, and closes the connection as soon as the version bytes are received. We consider this approach stealthy. Found versions are written to disk.",

	Flags: []cli.Flag{
		&cli.IntFlag{
			Name:        "threads",
			Aliases:     []string{"t"},
			Usage:       "maximum number of concurrent threads (connections)",
			Destination: &flagBannerThreads,
		},

		&cli.DurationFlag{
			Name:        "timeout",
			Aliases:     []string{"T"},
			Usage:       "TCP connection timeout",
			Destination: &flagBannerTimeout,

			Value: time.Second * 5,
		},

		&cli.StringFlag{
			Name:        "hosts",
			Aliases:     []string{"H"},
			Usage:       "load banner hosts `FILE` in IP:PORT format",
			Destination: &flagBannerHostsFile,

			Value: "scan.log",
		},

		&cli.StringFlag{
			Name:        "output",
			Aliases:     []string{"o"},
			Usage:       "write found banners to `FILE` in IP:PORT:BANNER format",
			Destination: &flagBannerOutputFile,

			Value: "banner.log",
		},
	},

	Action: actionBanner,
}

func actionBanner(c *cli.Context) error {
	signalC := make(chan os.Signal, 1)
	signal.Notify(signalC, os.Interrupt, os.Kill, syscall.SIGTERM)

	logFile, err := os.OpenFile(flagBannerOutputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
	if err != nil {
		return err
	}
	defer logFile.Close()

	hosts, err := load.Hosts(flagBannerHostsFile)
	if err != nil {
		log.Fatal(err)
	}
	hostsLen := len(hosts)
	log.Infof("loaded %v hosts from %v file", len(hosts), flagBannerHostsFile)

	if flagBannerThreads == 0 {
		flagBannerThreads = setThreads(hostsLen)
		log.Infof("automatically set threads %v, use --threads to override.", flagBannerThreads)
	}
	// bannerThreadsC allows us to limit max number of goroutines
	bannerThreadsC = make(chan struct{}, flagBannerThreads)

	bar := pkg.NewProgressBar(hostsLen, "Extract SSH Banners")
	defer bar.Close()

	var vuln = vulnCounter{}
	// wg allows us to wait for unfinished goroutines
	var wg = &sync.WaitGroup{}
	for _, host := range hosts {
		select {
		case s := <-signalC:
			log.Warnf("interrupted by signal %v", s)
			break
		default:
		}

		wg.Add(1)
		bannerThreadsC <- struct{}{}
		go func(hostPort string) {
			defer func() {
				bar.Add(1)
				<-bannerThreadsC
				wg.Done()
			}()

			version, err := banner.Extract(hostPort, flagBannerTimeout)
			if err != nil {
				log.Debugf("%v --> %v", hostPort, err)
				if strings.Contains(err.Error(), "too many open files") {
					log.Fatal("too many open file descriptors: use `ulimit -n int` to grow them.")
				}
				return
			}

			data := fmt.Sprintf("%v:%v\n", hostPort, version)
			err = pkg.WriteTo(logFile, data)
			if err != nil {
				log.Error(err)
			}

			vuln.Add()

			if len(version) > 20 {
				version = version[:20]
			}
			bar.Describe(fmt.Sprintf("%20s found[%v]", version, vuln.Get()))
		}(host.String())
	}

	fmt.Printf("\r\n")
	log.Info("waiting for connections to timeout and close...")
	wg.Wait()
	close(bannerThreadsC)
	bar.Describe(fmt.Sprintf("found[%v]", vuln.Get()))
	log.Infof("created %v in HOST:PORT:BANNER format", flagBannerOutputFile)
	return nil
}

// vulnCounter keeps the score of how many vulnerable hosts have been found.
type vulnCounter struct {
	mu    sync.Mutex
	found int
}

// Add is self describing.
func (f *vulnCounter) Add() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.found++
}

// Get is self describing.
func (f *vulnCounter) Get() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.found
}

// setThreads returns the number of allowed goroutines based on the number
// of hosts.
func setThreads(input int) int {
	fdLimit := rlimit.Get().Max
	if fdLimit == 0 {
		// in case we're unable to get the fd limit value
		fdLimit = uint64(input)
	}
	// set threads to 80% of Max
	threads := float64(fdLimit) / 1.20
	if threads > float64(input) {
		// set threads to half the size of input
		// when input is less than the system limit
		threads = float64(input) / 2
	}
	// anomaly check
	if threads < 1 {
		threads = 1
	}
	return int(threads)
}
