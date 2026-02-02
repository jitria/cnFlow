// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package resolver

import (
    "sync"
    "log"
)

type resolverHandler struct {
    waitGroup *sync.WaitGroup
    stopChan  chan struct{}

    nodeStopChans map[string]chan struct{}
    podStopChans  map[string]chan struct{}
    mu            sync.RWMutex
}

var ResolverH *resolverHandler

// InitResolverHandler creates and initializes the resolver handler.
func InitResolverHandler(stopChan chan struct{}) error {
    ResolverH = &resolverHandler{
        stopChan:      stopChan,
        waitGroup:     new(sync.WaitGroup),
        nodeStopChans: make(map[string]chan struct{}),
        podStopChans:  make(map[string]chan struct{}),
    }

    log.Printf("[Resolver] Resolver handler initialized")
    return nil
}

// StartResolverHandler is a placeholder for future start-up logic.
func StartResolverHandler() error {
    log.Printf("[Resolver] Resolver handler started")
    return nil
}

// WaitShutdown closes all eBPF stop channels and blocks until all goroutines finish.
func WaitShutdown() {
    log.Printf("[Resolver] Starting shutdown process...")

    ResolverH.mu.Lock()
    for key, stopChan := range ResolverH.nodeStopChans {
        close(stopChan)
        delete(ResolverH.nodeStopChans, key)
    }
    for key, stopChan := range ResolverH.podStopChans {
        close(stopChan)
        delete(ResolverH.podStopChans, key)
    }
    ResolverH.mu.Unlock()

    ResolverH.waitGroup.Wait()
    log.Printf("[Resolver] All resolver goroutines stopped")
}
