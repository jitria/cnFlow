// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package collector

import (
    "log"
    "net"
    "sync"

    "google.golang.org/grpc"
)

type collectorHandler struct {
    waitGroup *sync.WaitGroup
    stopChan  chan struct{}

    netListener net.Listener
    grpcServer  *grpc.Server
    grpcService *ColService
}

var CollectorH *collectorHandler

// InitCollectorHandler initializes the collector handler with a stop channel.
func InitCollectorHandler(stopChan chan struct{}) error {
    CollectorH = &collectorHandler{
        stopChan:  stopChan,
        waitGroup: new(sync.WaitGroup),

        netListener: nil,
        grpcServer:  nil,
        grpcService: new(ColService),
    }
    return nil
}

// StartCollectorHandler starts the collector handler by launching the gRPC server in a goroutine.
func StartCollectorHandler() error {
    CollectorH.waitGroup.Add(1)
    go func() {
        defer CollectorH.waitGroup.Done()
        startGRPCServer()
    }()

    return nil
}

// WaitShutdown waits for all collector goroutines to complete.
func WaitShutdown() {
    CollectorH.waitGroup.Wait()
    log.Printf("[CollectorH] All collector goroutines stopped")
}
