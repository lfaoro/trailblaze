package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/lfaoro/trailblaze/app"
)

var appBanner = fmt.Sprintf(`
  *   )                (    (   (
 )  /( (       )  (   )\ ( )\  )\    )        (
 ( )(_)))(   ( /(  )\ ((_))((_)((_)( /(  (    ))\
(_(_())(()\  )(_))((_) _ ((_)_  _  )(_)) )\  /((_)
|_   _| ((_)((_)_  (_)| | | _ )| |((_)_ ((_)(_))
  | |  | '_|/ _  | | || | | _ \| |/ _  ||_ // -_)
  |_|  |_|  \__,_| |_||_| |___/|_|\__,_|/__|\___|
                     github.com/lfaoro/trailblaze

Please note that using this software constitutes
your acceptance of our --terms.
`)

func main() {

	rand.Seed(time.Now().UnixNano())
	rn := rand.Intn(7) + 30

	color.Set(color.Attribute(rn))
	fmt.Fprint(os.Stderr, appBanner)
	color.Unset()

	app.App()
}
