// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package config

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/viper"
)

type ManagerConfig struct {
	HostName string

	ManagerAddr string
	ManagerPort string
}

// GlobalConfig is the singleton instance of ManagerConfig.
var GlobalConfig ManagerConfig

// flag names
const (
	HostName = "hostname"

	ManagerAddr = "managerAddr"
  	ManagerPort = "managerPort"
)

// readCmdLineParams parses CLI flags and sets Viper defaults.
func readCmdLineParams() {
	defaultHost := "user"
	if osName, err := os.Hostname(); err == nil {
		defaultHost = osName
	} else {
		log.Printf("[GlobalConfig] could not retrieve OS hostname: %v", err)
	}

	hostName := flag.String(HostName, defaultHost, "Name of the host")

	managerAddrStr := flag.String(ManagerAddr, "0.0.0.0", "Address for Operator gRPC")
	managerPortStr := flag.String(ManagerPort, "5317", "Port for Operator gRPC")

	flag.Parse()

	var flags []string
	flag.VisitAll(func(f *flag.Flag) {
		flags = append(flags, fmt.Sprintf("%s:%v", f.Name, f.Value))
	})
	log.Printf("[GlobalConfig] Arguments [%s]", strings.Join(flags, " "))

	viper.SetDefault(HostName, *hostName)

	viper.SetDefault(ManagerAddr, *managerAddrStr)
	viper.SetDefault(ManagerPort, *managerPortStr)
}

// LoadConfig reads CLI flags, environment variables, and populates GlobalConfig.
func LoadConfig() {
	readCmdLineParams()

	viper.AutomaticEnv()

	GlobalConfig.HostName = viper.GetString(HostName)

	GlobalConfig.ManagerAddr = viper.GetString(ManagerAddr)
	GlobalConfig.ManagerPort = viper.GetString(ManagerPort)

	log.Printf("[GlobalConfig] Config [%+v]", GlobalConfig)
}
