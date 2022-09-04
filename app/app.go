package app

import (
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

func init() {
	log.SetFormatter(&log.TextFormatter{
		ForceColors:      true,
		DisableTimestamp: true,
	})
}

// https://github.com/urfave/cli/blob/main/docs/v2/manual.md
func App() {
	app := &cli.App{
		Name:      "trailblaze",
		Usage:     " TrailBlaze - SSH Pentest & Audit",
		Version:   "v0.1.1",
		Compiled:  time.Now(),
		Copyright: "(c) Leonardo Faoro",

		UseShortOptionHandling: true,
		EnableBashCompletion:   true,
		HideHelpCommand:        true,

		Commands: []*cli.Command{
			bannerCmd,
			scanCmd,
		},

		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:   "debug",
				Usage:  "print debug logs",
				Hidden: true,
			},

			&cli.BoolFlag{
				Name:  "terms",
				Usage: "print terms & conditions",
			},
		},

		Before: func(ctx *cli.Context) error {
			if ctx.Bool("debug") {
				log.SetLevel(log.DebugLevel)
			}

			if ctx.Bool("terms") {
				showTerms()
				os.Exit(0)
			}
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Error(err)
	}
}

func showTerms() {
	fmt.Printf(`
This tool should be used for authorized penetration testing and/or educational purposes only.
Any misuse of this software will not be the responsibility of the author or of any other collaborator.
Use it on your own systems or obtain explicit permission from the systems owner.

Usage of this software for connecting to targets without prior mutual consent may be illegal in your jurisdiction.
It is the end user's responsibility to obey all applicable local, state and federal laws.
We assume no liability and are not responsible for any misuse or damage caused.
`)
}
