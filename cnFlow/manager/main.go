// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package main


import (
	"cnFlow/manager/config"
	"cnFlow/manager/core"
)

// main loads the configuration and starts the manager.
func main() {
	config.LoadConfig()
	core.Manager()
}