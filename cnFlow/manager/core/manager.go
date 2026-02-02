// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package core

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"cnFlow/manager/collector"
	"cnFlow/manager/mixer"
	"cnFlow/manager/parser"
)

type managerType struct {
	waitGroup *sync.WaitGroup
	stopChan  chan struct{}
}

var ManagerH *managerType

// init initializes the ManagerH instance
func init() {
	ManagerH = &managerType{
		stopChan:  make(chan struct{}),
		waitGroup: new(sync.WaitGroup),
	}
}

// DestroyManagerH destroys the ManagerH instance
func (ManagerH *managerType) DestroyManagerH() {
	close(ManagerH.stopChan)

	collector.WaitShutdown()
	parser.WaitShutdown()
	mixer.WaitShutdown()

	ManagerH.waitGroup.Wait()

	log.Fatalf("[ManagerH] Stopped all")
}

// GetOSSigChannel gets the OS signal channel
func GetOSSigChannel() chan os.Signal {
	c := make(chan os.Signal, 1)

	signal.Notify(c,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		os.Interrupt)

	return c
}

// Manager initializes the Manager instance and starts the node and pod controllers
func Manager() {
	var err error

	log.Printf("[ManagerH] Starting ManagerH...")

	if err = mixer.InitMixerHandler(ManagerH.stopChan); err != nil {
		log.Printf("[ManagerH] Error initializing MixerHandler: %v", err)
		ManagerH.DestroyManagerH()
	}
	log.Printf("[ManagerH] MixerHandler initialized successfully")

	if err = collector.InitCollectorHandler(ManagerH.stopChan); err != nil {
		log.Printf("[ManagerH] Error initializing CollectorHandler: %v", err)
		ManagerH.DestroyManagerH()
	}
	log.Printf("[ManagerH] CollectorHandler initialized successfully")

	if err = parser.InitParserHandler(ManagerH.stopChan); err != nil {
		log.Printf("[ManagerH] Error initializing ParserHandler: %v", err)
		ManagerH.DestroyManagerH()
	}
	log.Printf("[ManagerH] ParserHandler initialized successfully")


	if err = collector.StartCollectorHandler(); err != nil {
		log.Printf("[ManagerH] Error starting CollectorHandler: %v", err)
		ManagerH.DestroyManagerH()
	}
	log.Printf("[ManagerH] CollectorHandler started successfully")

	if err = mixer.StartMixerHandler(); err != nil {
		log.Printf("[ManagerH] Error starting MixerHandler: %v", err)
		ManagerH.DestroyManagerH()
	}
	log.Printf("[ManagerH] MixerHandler started successfully")

	if err = parser.StartParserHandler(); err != nil {
		log.Printf("[ManagerH] Error starting ParserHandler: %v", err)
		ManagerH.DestroyManagerH()
	}
	log.Printf("[ManagerH] ParserHandler started successfully")


	sigChan := GetOSSigChannel()
	<-sigChan
	log.Printf("[ManagerH] Got a signal to terminate ManagerH")

	ManagerH.DestroyManagerH()
}
