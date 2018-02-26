package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/openshift/image-build-daemon/pkg/cmd"
	"github.com/openshift/image-build-daemon/pkg/logs"
)

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	rand.Seed(time.Now().UTC().UnixNano())

	command := cmd.New("")
	command.PersistentFlags().AddGoFlag(flag.Lookup("v"))
	if err := command.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
