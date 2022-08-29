package pkg

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/denisbrodbeck/machineid"
	"github.com/schollz/progressbar/v3"
	log "github.com/sirupsen/logrus"
)

func SplitHost(hostPort string) (ip string, port string) {
	split := strings.Split(hostPort, ":")
	return split[0], split[1]
}

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

var fileMu sync.Mutex

func WriteTo(file *os.File, data string) error {
	fileMu.Lock()
	defer fileMu.Unlock()
	if _, err := file.WriteString(data); err != nil {
		return err
	}
	return nil
}

func NewProgressBar(max int, name string) *progressbar.ProgressBar {
	bar := progressbar.NewOptions64(
		int64(max),
		progressbar.OptionSetDescription(name),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionSetPredictTime(true),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[blue]=[reset]",
			SaucerHead:    "[cyan]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),

		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowBytes(false),
		progressbar.OptionSetWidth(20),
		progressbar.OptionThrottle(300*time.Millisecond),
		// progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() {
			fmt.Printf("\n")
		}),
		progressbar.OptionSpinnerType(14),
		// progressbar.OptionFullWidth(),
	)

	bar.RenderBlank()

	return bar
}

func MachineID() (string, error) {
	return machineid.ProtectedID("TrailBlaze")
}

func TimeElapsed(now time.Time, then time.Time, full bool) string {
	var parts []string
	var text string

	isPlural := func(x float64) string {
		if int(x) == 1 {
			return ""
		}
		return "s"
	}

	year2, month2, day2 := now.Date()
	hour2, minute2, second2 := now.Clock()

	year1, month1, day1 := then.Date()
	hour1, minute1, second1 := then.Clock()

	year := math.Abs(float64(int(year2 - year1)))
	month := math.Abs(float64(int(month2 - month1)))
	day := math.Abs(float64(int(day2 - day1)))
	hour := math.Abs(float64(int(hour2 - hour1)))
	minute := math.Abs(float64(int(minute2 - minute1)))
	second := math.Abs(float64(int(second2 - second1)))

	week := math.Floor(day / 7)

	if year > 0 {
		parts = append(parts, strconv.Itoa(int(year))+" year"+isPlural(year))
	}

	if month > 0 {
		parts = append(parts, strconv.Itoa(int(month))+" month"+isPlural(month))
	}

	if week > 0 {
		parts = append(parts, strconv.Itoa(int(week))+" week"+isPlural(week))
	}

	if day > 0 {
		parts = append(parts, strconv.Itoa(int(day))+" day"+isPlural(day))
	}

	if hour > 0 {
		parts = append(parts, strconv.Itoa(int(hour))+" hour"+isPlural(hour))
	}

	if minute > 0 {
		parts = append(parts, strconv.Itoa(int(minute))+" minute"+isPlural(minute))
	}

	if second > 0 {
		parts = append(parts, strconv.Itoa(int(second))+" second"+isPlural(second))
	}

	if now.After(then) {
		text = " ago"
	} else {
		text = " after"
	}

	if len(parts) == 0 {
		return "just now"
	}

	if full {
		return strings.Join(parts, ", ") + text
	}
	return parts[0] + text
}
