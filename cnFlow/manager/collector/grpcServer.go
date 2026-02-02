// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package collector

import (
    "fmt"
    "net"
    "io"
    "log"

    "cnFlow/protobuf"
    "cnFlow/manager/config"
    "cnFlow/manager/parser"
    "cnFlow/manager/mixer"

    "google.golang.org/grpc"
)

type ColService struct {
    protobuf.UnimplementedIctcServer
}

// startGRPCServer starts the gRPC server and blocks until stop signal is received.
func startGRPCServer() {
    addr := fmt.Sprintf("%s:%s", config.GlobalConfig.ManagerAddr, config.GlobalConfig.ManagerPort)
    log.Printf("[CollectorH] Starting gRPC server on %s", addr)

    var err error
    CollectorH.netListener, err = net.Listen("tcp", addr)
    if err != nil {
        log.Printf("[CollectorH] Failed to listen on %s: %v", addr, err)
        return
    }

    CollectorH.grpcServer = grpc.NewServer()
    protobuf.RegisterIctcServer(CollectorH.grpcServer, CollectorH.grpcService)

    go func() {
        if err := CollectorH.grpcServer.Serve(CollectorH.netListener); err != nil {
            log.Printf("[CollectorH] gRPC server error: %v", err)
        }
    }()

    log.Printf("[CollectorH] gRPC server started successfully")

    <-CollectorH.stopChan

    shutdownGRPCServer()
}

// shutdownGRPCServer gracefully shuts down the gRPC server.
func shutdownGRPCServer() {
    log.Printf("[CollectorH] Shutting down gRPC server...")

    if CollectorH.grpcServer != nil {
        CollectorH.grpcServer.GracefulStop()
    }

    if CollectorH.netListener != nil {
        _ = CollectorH.netListener.Close()
    }

    log.Printf("[CollectorH] gRPC server shutdown completed")
}

// SyncPods handles the streaming RPC for synchronizing Pod information.
func (s *ColService) SyncPods(stream protobuf.Ictc_SyncPodsServer) error {
    log.Printf("[CollectorH] Starting Pod sync stream")

    for {
        pod, err := stream.Recv()
        if err == io.EOF {
            log.Printf("[CollectorH] Pod sync stream completed")
            return stream.SendAndClose(&protobuf.Ack{Success: true})
        }
        if err != nil {
            log.Printf("[CollectorH] Error receiving pod data: %v", err)
            return err
        }

        // Pass Pod information to Mixer
        mixer.AddPod(pod)

        log.Printf("[CollectorH] Received Pod: %s/%s (IP: %s)", pod.Namespace, pod.Name, pod.PodIp)
        log.Printf("[CollectorH] Pod Info: %+v", pod)
    }
}

// SyncNodes handles the streaming RPC for synchronizing Node information.
func (s *ColService) SyncNodes(stream protobuf.Ictc_SyncNodesServer) error {
    log.Printf("[CollectorH] Starting Node sync stream")

    for {
        node, err := stream.Recv()
        if err == io.EOF {
            log.Printf("[CollectorH] Node sync stream completed")
            return stream.SendAndClose(&protobuf.Ack{Success: true})
        }
        if err != nil {
            log.Printf("[CollectorH] Error receiving node data: %v", err)
            return err
        }

        // Pass Node information to Mixer
        mixer.AddNode(node)

        log.Printf("[CollectorH] Received Node: %s (IP: %s)", node.Name, node.HostIp)
        log.Printf("[CollectorH] Node Info: %+v", node)
    }
}

// HTTPEvents handles the streaming RPC for HTTP events.
func (s *ColService) HTTPEvents(stream protobuf.Ictc_HTTPEventsServer) error {
    log.Printf("[CollectorH] Starting HTTP events stream")

    for {
        event, err := stream.Recv()
        if err == io.EOF {
            log.Printf("[CollectorH] HTTP events stream completed")
            return stream.SendAndClose(&protobuf.Ack{Success: true})
        }
        if err != nil {
            log.Printf("[CollectorH] Error receiving HTTP event: %v", err)
            return err
        }

        // Pass to Parser
        parser.ProcessHTTPEvent(event)
    }
}

// HTTP2Events handles the streaming RPC for HTTP2 events.
func (s *ColService) HTTP2Events(stream protobuf.Ictc_HTTP2EventsServer) error {
    log.Printf("[CollectorH] Starting HTTP2 events stream")

    for {
        event, err := stream.Recv()
        if err == io.EOF {
            log.Printf("[CollectorH] HTTP2 events stream completed")
            return stream.SendAndClose(&protobuf.Ack{Success: true})
        }
        if err != nil {
            log.Printf("[CollectorH] Error receiving HTTP2 event: %v", err)
            return err
        }

        // Pass to Parser
        parser.ProcessHTTP2Event(event)
    }
}

// DNSEvents handles the streaming RPC for DNS events.
func (s *ColService) DNSEvents(stream protobuf.Ictc_DNSEventsServer) error {
    log.Printf("[CollectorH] Starting DNS events stream")

    for {
        event, err := stream.Recv()
        if err == io.EOF {
            log.Printf("[CollectorH] DNS events stream completed")
            return stream.SendAndClose(&protobuf.Ack{Success: true})
        }
        if err != nil {
            log.Printf("[CollectorH] Error receiving DNS event: %v", err)
            return err
        }

        // Pass to Parser
        parser.ProcessDNSEvent(event)
    }
}

// RedisEvents handles the streaming RPC for Redis events.
func (s *ColService) RedisEvents(stream protobuf.Ictc_RedisEventsServer) error {
    log.Printf("[CollectorH] Starting Redis events stream")

    for {
        event, err := stream.Recv()
        if err == io.EOF {
            log.Printf("[CollectorH] Redis events stream completed")
            return stream.SendAndClose(&protobuf.Ack{Success: true})
        }
        if err != nil {
            log.Printf("[CollectorH] Error receiving Redis event: %v", err)
            return err
        }

        // Pass to Parser
        parser.ProcessRedisEvent(event)
    }
}

// ICMPEvents handles the streaming RPC for ICMP events.
func (s *ColService) ICMPEvents(stream protobuf.Ictc_ICMPEventsServer) error {
    log.Printf("[CollectorH] Starting ICMP events stream")

    for {
        event, err := stream.Recv()
        if err == io.EOF {
            log.Printf("[CollectorH] ICMP events stream completed")
            return stream.SendAndClose(&protobuf.Ack{Success: true})
        }
        if err != nil {
            log.Printf("[CollectorH] Error receiving ICMP event: %v", err)
            return err
        }

        // Pass to Parser
        parser.ProcessICMPEvent(event)
    }
}

// KafkaEvents handles the streaming RPC for Kafka events.
func (s *ColService) KafkaEvents(stream protobuf.Ictc_KafkaEventsServer) error {
    log.Printf("[CollectorH] Starting Kafka events stream")

    for {
        event, err := stream.Recv()
        if err == io.EOF {
            log.Printf("[CollectorH] Kafka events stream completed")
            return stream.SendAndClose(&protobuf.Ack{Success: true})
        }
        if err != nil {
            log.Printf("[CollectorH] Error receiving Kafka event: %v", err)
            return err
        }

        // Pass to Parser
        parser.ProcessKafkaEvent(event)
    }
}
