// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package core

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"cnFlow/agent/uploader"
	"cnFlow/agent/k8s"
	"cnFlow/agent/attacher"
	"cnFlow/agent/resolver"
)

type agentType struct {
	waitGroup *sync.WaitGroup
	stopChan  chan struct{}
}

var AgentH *agentType

// init initializes the singleton agent instance with a stop channel and wait group.
func init() {
	AgentH = &agentType{
		stopChan:  make(chan struct{}),
		waitGroup: new(sync.WaitGroup),
	}
}

// DestroyAgentH performs a graceful shutdown of all agent components.
func (AgentH *agentType) DestroyAgentH() {
	log.Printf("[AgentH] Starting shutdown process...")

    close(AgentH.stopChan)

    log.Printf("[AgentH] Waiting for resolver shutdown...")
    resolver.WaitShutdown()

    log.Printf("[AgentH] Waiting for attacher shutdown...")
    attacher.WaitShutdown()

    log.Printf("[AgentH] Waiting for k8s shutdown...")
    k8s.WaitShutdown()

    log.Printf("[AgentH] Waiting for uploader shutdown...")
    uploader.WaitShutdown()

    AgentH.waitGroup.Wait()

    log.Printf("[AgentH] All components stopped successfully")
    os.Exit(0)
}

// GetOSSigChannel returns a channel that receives OS termination signals.
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

// Agent initializes and starts all agent components, then waits for a termination signal.
func Agent() {
	var err error

	log.Printf("[AgentH] Starting AgentH...")

	if err = uploader.InitUploaderHandler(AgentH.stopChan); err != nil {
		log.Printf("[AgentH] Error initializing UploaderHandler: %v", err)
		AgentH.DestroyAgentH()
	}
	log.Printf("[AgentH] UploaderHandler initialized successfully")

	if err = attacher.InitAttacherHandler(AgentH.stopChan); err != nil {
		log.Printf("[AgentH] Error initializing AttacherHandler: %v", err)
		AgentH.DestroyAgentH()
	}
	log.Printf("[AgentH] AttacherHandler initialized successfully")

	if err = resolver.InitResolverHandler(AgentH.stopChan); err != nil {
		log.Printf("[AgentH] Error initializing ResolverHandler: %v", err)
		AgentH.DestroyAgentH()
	}
	log.Printf("[AgentH] ResolverHandler initialized successfully")

	if err = k8s.InitK8sHandler(AgentH.stopChan); err != nil {
		log.Printf("[AgentH] Error initializing K8sHandler: %v", err)
		AgentH.DestroyAgentH()
	}
	log.Printf("[AgentH] K8sHandler initialized successfully")

	if err = uploader.StartUploaderHandler(); err != nil {
		log.Printf("[AgentH] Error starting UploaderHandler: %v", err)
		AgentH.DestroyAgentH()
	}
	log.Printf("[AgentH] UploaderHandler started successfully")

	if err = attacher.StartAttacherHandler(); err != nil {
		log.Printf("[AgentH] Error starting AttacherHandler: %v", err)
		AgentH.DestroyAgentH()
	}
	log.Printf("[AgentH] AttacherHandler started successfully")

	if err = resolver.StartResolverHandler(); err != nil {
		log.Printf("[AgentH] Error starting ResolverHandler: %v", err)
		AgentH.DestroyAgentH()
	}
	log.Printf("[AgentH] ResolverHandler started successfully")

	if err = k8s.StartK8sHandler(); err != nil {
		log.Printf("[AgentH] Error starting K8sHandler: %v", err)
		AgentH.DestroyAgentH()
	}
	log.Printf("[AgentH] K8sHandler started successfully")

	sigChan := GetOSSigChannel()
	<-sigChan
	log.Printf("[AgentH] Got a signal to terminate AgentH")

	AgentH.DestroyAgentH()
}
