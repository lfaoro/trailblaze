package load

import (
	log "github.com/sirupsen/logrus"
)

var Debug = false

func init() {
	log.SetFormatter(&log.TextFormatter{
		ForceColors:      true,
		DisableTimestamp: true,
	})
	if Debug {
		log.SetLevel(log.DebugLevel)
	}
}
