package load_test

import (
	"testing"

	"github.com/lfaoro/trailblaze/pkg/load"
)

func TestLoadHosts(t *testing.T) {
	h, err := load.Hosts("./testdata/host_file.txt")
	if err != nil {
		t.Fail()
	}
	t.Log(h)
}
