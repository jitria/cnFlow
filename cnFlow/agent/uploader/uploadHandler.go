// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package uploader

import (
    "context"
    "fmt"
    "log"
    "sync"

    "cnFlow/protobuf"
    "cnFlow/agent/config"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

type uploaderHandler struct {
    waitGroup *sync.WaitGroup
    stopChan  chan struct{}

    grpcClient protobuf.IctcClient

    podStream  protobuf.Ictc_SyncPodsClient
    nodeStream protobuf.Ictc_SyncNodesClient

    httpStream   protobuf.Ictc_HTTPEventsClient
    http2Stream  protobuf.Ictc_HTTP2EventsClient
    dnsStream    protobuf.Ictc_DNSEventsClient
    redisStream  protobuf.Ictc_RedisEventsClient
    icmpStream   protobuf.Ictc_ICMPEventsClient
    kafkaStream  protobuf.Ictc_KafkaEventsClient

    PodMap  map[string]*protobuf.PodInfo
    NodeMap map[string]*protobuf.NodeInfo
    mu      sync.RWMutex
}

var UploaderH *uploaderHandler

// InitUploaderHandler creates the uploader handler with empty maps.
func InitUploaderHandler(stopChan chan struct{}) error {
    UploaderH = &uploaderHandler{
        stopChan:  stopChan,
        waitGroup: new(sync.WaitGroup),
        PodMap:    make(map[string]*protobuf.PodInfo),
        NodeMap:   make(map[string]*protobuf.NodeInfo),
    }
    return nil
}

// StartUploaderHandler connects to the manager gRPC server and opens all streaming RPCs.
func StartUploaderHandler() error {
    UploaderH.waitGroup.Add(1)
    go func() {
        defer UploaderH.waitGroup.Done()

        grpcClient, err := connectToManager()
        if err != nil {
            log.Printf("[UploaderH] Failed to connect to Manager's gRPC server: %v", err)
            return
        }
        UploaderH.grpcClient = grpcClient

        if UploaderH.podStream, err = UploaderH.grpcClient.SyncPods(context.Background()); err != nil {
            log.Printf("[UploaderH] fail to open SyncPods: %v", err)
            return
        }
        if UploaderH.nodeStream, err = UploaderH.grpcClient.SyncNodes(context.Background()); err != nil {
            log.Printf("[UploaderH] fail to open SyncNodes: %v", err)
            return
        }

        if UploaderH.httpStream, err = UploaderH.grpcClient.HTTPEvents(context.Background()); err != nil {
            log.Printf("[UploaderH] fail to open HTTPEvents: %v", err)
            return
        }
        if UploaderH.http2Stream, err = UploaderH.grpcClient.HTTP2Events(context.Background()); err != nil {
            log.Printf("[UploaderH] fail to open HTTP2Events: %v", err)
            return
        }
        if UploaderH.dnsStream, err = UploaderH.grpcClient.DNSEvents(context.Background()); err != nil {
            log.Printf("[UploaderH] fail to open DNSEvents: %v", err)
            return
        }
        if UploaderH.redisStream, err = UploaderH.grpcClient.RedisEvents(context.Background()); err != nil {
            log.Printf("[UploaderH] fail to open RedisEvents: %v", err)
            return
        }
        if UploaderH.icmpStream, err = UploaderH.grpcClient.ICMPEvents(context.Background()); err != nil {
            log.Printf("[UploaderH] fail to open ICMPEvents: %v", err)
            return
        }
        if UploaderH.kafkaStream, err = UploaderH.grpcClient.KafkaEvents(context.Background()); err != nil {
            log.Printf("[UploaderH] fail to open KafkaEvents: %v", err)
            return
        }

        log.Printf("[UploaderH] gRPC streams established successfully")

        <-UploaderH.stopChan

        if UploaderH.podStream != nil {
            UploaderH.podStream.CloseSend()
        }
        if UploaderH.nodeStream != nil {
            UploaderH.nodeStream.CloseSend()
        }
        if UploaderH.httpStream != nil {
            UploaderH.httpStream.CloseSend()
        }
        if UploaderH.http2Stream != nil {
            UploaderH.http2Stream.CloseSend()
        }
        if UploaderH.dnsStream != nil {
            UploaderH.dnsStream.CloseSend()
        }
        if UploaderH.redisStream != nil {
            UploaderH.redisStream.CloseSend()
        }
        if UploaderH.icmpStream != nil {
            UploaderH.icmpStream.CloseSend()
        }
        if UploaderH.kafkaStream != nil {
            UploaderH.kafkaStream.CloseSend()
        }
    }()
    return nil
}

// connectToManager dials the manager gRPC server and returns a client.
func connectToManager() (protobuf.IctcClient, error) {
    managerAddr := fmt.Sprintf("%s:%s", config.GlobalConfig.ManagerAddr, config.GlobalConfig.ManagerPort)

    conn, err := grpc.Dial(managerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        log.Printf("[UploaderH] Failed to connect to Manager's gRPC server at %s: %v", managerAddr, err)
        return nil, err
    }

    client := protobuf.NewIctcClient(conn)

    return client, nil
}

// WaitShutdown blocks until all uploader goroutines have finished.
func WaitShutdown() {
    UploaderH.waitGroup.Wait()
    log.Printf("[UploaderH] All uploader goroutines stopped")
}
