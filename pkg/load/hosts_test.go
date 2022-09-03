package load_test

import (
	"testing"

	"github.com/lfaoro/trailblaze/pkg/load"
)

func TestLoadHosts(t *testing.T) {
	h := load.Hosts("./testdata/host_file.txt")
	t.Log(h)
}
