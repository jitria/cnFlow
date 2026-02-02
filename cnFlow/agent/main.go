// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package main


import (
	"cnFlow/agent/config"
	"cnFlow/agent/core"
)

// main loads the configuration and starts the agent.
func main() {
	config.LoadConfig()
	core.Agent()
}