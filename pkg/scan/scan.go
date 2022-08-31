package scan

import (
	"errors"
	"fmt"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
)

type Scanner struct {
	mu        sync.Mutex
	file      *os.File
	openPorts int
	scanFails map[string]int
}

func NewScanner(logFile string) *Scanner {
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatal(err)
	}
	return &Scanner{
		mu:        sync.Mutex{},
		openPorts: 0,
		scanFails: map[string]int{},
		file:      file,
	}
}

func (s *Scanner) AddOpenPort() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.openPorts++
}

func (s *Scanner) OpenPorts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.openPorts
}

func (s *Scanner) Save(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.file.WriteString(text + "\n")
	if err != nil {
		log.Debug(err)
		log.Errorf("failed to write %v to file", text)
	}
}

func (s *Scanner) Close() {
	s.file.Close()
}

func (s *Scanner) AddFailReason(err error) {
	e := errors.Unwrap(err)
	if e == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanFails[e.Error()]++
}

func (s *Scanner) PrintStats() {
	s.mu.Lock()
	defer s.mu.Unlock()
	var total int
	for k, v := range s.scanFails {
		total += v
		fmt.Printf("(%5d)  %v\n", v, k)
	}
	fmt.Printf("(%5d)  total failed\n", total)
}
