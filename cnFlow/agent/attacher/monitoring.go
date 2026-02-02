// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package attacher

import (
    "errors"
    "log"
    "sync"

    "github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type http_event -type http2_event -type dns_event -type redis_event -type icmp_event -type kafka_event -tags linux -cflags "-g -O3" TC ./BPF/tc.bpf.c

// startProtocolMonitoring creates ring buffer readers for all protocol queues and starts reading goroutines.
func startProtocolMonitoring(stopChan <-chan struct{}, ctx *BPFContext) {
    log.Printf("[Attacher] Initializing protocol monitoring for interface %s", ctx.Iface.Name)

    var readers []*ringbuf.Reader
    var wg sync.WaitGroup

    if httpReader, err := ringbuf.NewReader(ctx.TCbpfObjs.HttpQueue); err != nil {
        log.Printf("[Attacher] Failed to create HTTP ring buffer reader: %v", err)
    } else {
        log.Printf("[Attacher] HTTP ring buffer reader created successfully")
        readers = append(readers, httpReader)
        wg.Add(1)
        go func() {
            defer wg.Done()
            readHTTPEvents(httpReader, stopChan)
            httpReader.Close()
        }()
    }

    if http2Reader, err := ringbuf.NewReader(ctx.TCbpfObjs.Http2Queue); err != nil {
        log.Printf("[Attacher] Failed to create HTTP2 ring buffer reader: %v", err)
    } else {
        log.Printf("[Attacher] HTTP2 ring buffer reader created successfully")
        readers = append(readers, http2Reader)
        wg.Add(1)
        go func() {
            defer wg.Done()
            readHTTP2Events(http2Reader, stopChan)
            http2Reader.Close()
        }()
    }

    if dnsReader, err := ringbuf.NewReader(ctx.TCbpfObjs.DnsQueue); err != nil {
        log.Printf("[Attacher] Failed to create DNS ring buffer reader: %v", err)
    } else {
        log.Printf("[Attacher] DNS ring buffer reader created successfully")
        readers = append(readers, dnsReader)
        wg.Add(1)
        go func() {
            defer wg.Done()
            readDNSEvents(dnsReader, stopChan)
            dnsReader.Close()
        }()
    }

    if redisReader, err := ringbuf.NewReader(ctx.TCbpfObjs.RedisQueue); err != nil {
        log.Printf("[Attacher] Failed to create Redis ring buffer reader: %v", err)
    } else {
        log.Printf("[Attacher] Redis ring buffer reader created successfully")
        readers = append(readers, redisReader)
        wg.Add(1)
        go func() {
            defer wg.Done()
            readRedisEvents(redisReader, stopChan)
            redisReader.Close()
        }()
    }

    if icmpReader, err := ringbuf.NewReader(ctx.TCbpfObjs.IcmpQueue); err != nil {
        log.Printf("[Attacher] Failed to create ICMP ring buffer reader: %v", err)
    } else {
        log.Printf("[Attacher] ICMP ring buffer reader created successfully")
        readers = append(readers, icmpReader)
        wg.Add(1)
        go func() {
            defer wg.Done()
            readICMPEvents(icmpReader, stopChan)
            icmpReader.Close()
        }()
    }

    if kafkaReader, err := ringbuf.NewReader(ctx.TCbpfObjs.KafkaQueue); err != nil {
        log.Printf("[Attacher] Failed to create Kafka ring buffer reader: %v", err)
    } else {
        log.Printf("[Attacher] Kafka ring buffer reader created successfully")
        readers = append(readers, kafkaReader)
        wg.Add(1)
        go func() {
            defer wg.Done()
            readKafkaEvents(kafkaReader, stopChan)
            kafkaReader.Close()
        }()
    }

    log.Printf("[Attacher] All protocol monitoring goroutines started for interface %s", ctx.Iface.Name)

    // Close all readers on stop signal to unblock Read() calls
    go func() {
        <-stopChan
        log.Printf("[Attacher] Stop signal received for interface %s", ctx.Iface.Name)
        for _, reader := range readers {
            reader.Close()
        }
    }()

    wg.Wait()
    log.Printf("[Attacher] All monitoring goroutines stopped for interface %s", ctx.Iface.Name)
}

// readHTTPEvents continuously reads HTTP events from the ring buffer until stopped.
func readHTTPEvents(reader *ringbuf.Reader, stopChan <-chan struct{}) {
    log.Printf("[Attacher] Starting HTTP event reading loop")

    for {
        select {
        case <-stopChan:
            log.Printf("[Attacher] Stopping HTTP event reading loop")
            return
        default:
        }

        record, err := reader.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) {
                log.Printf("[Attacher] HTTP ring buffer closed")
                return
            }
            log.Printf("[Attacher] Failed to read HTTP event: %v", err)
            continue
        }

        if err := processHTTPEvent(record.RawSample); err != nil {
            log.Printf("[Attacher] Failed to process HTTP event: %v", err)
        }
    }
}

// readHTTP2Events continuously reads HTTP/2 events from the ring buffer until stopped.
func readHTTP2Events(reader *ringbuf.Reader, stopChan <-chan struct{}) {
    log.Printf("[Attacher] Starting HTTP2 event reading loop")

    for {
        select {
        case <-stopChan:
            log.Printf("[Attacher] Stopping HTTP2 event reading loop")
            return
        default:
        }

        record, err := reader.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) {
                log.Printf("[Attacher] HTTP2 ring buffer closed")
                return
            }
            log.Printf("[Attacher] Failed to read HTTP2 event: %v", err)
            continue
        }

        if err := processHTTP2Event(record.RawSample); err != nil {
            log.Printf("[Attacher] Failed to process HTTP2 event: %v", err)
        }
    }
}

// readDNSEvents continuously reads DNS events from the ring buffer until stopped.
func readDNSEvents(reader *ringbuf.Reader, stopChan <-chan struct{}) {
    log.Printf("[Attacher] Starting DNS event reading loop")

    for {
        select {
        case <-stopChan:
            log.Printf("[Attacher] Stopping DNS event reading loop")
            return
        default:
        }

        record, err := reader.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) {
                log.Printf("[Attacher] DNS ring buffer closed")
                return
            }
            log.Printf("[Attacher] Failed to read DNS event: %v", err)
            continue
        }

        if err := processDNSEvent(record.RawSample); err != nil {
            log.Printf("[Attacher] Failed to process DNS event: %v", err)
        }
    }
}

// readRedisEvents continuously reads Redis events from the ring buffer until stopped.
func readRedisEvents(reader *ringbuf.Reader, stopChan <-chan struct{}) {
    log.Printf("[Attacher] Starting Redis event reading loop")

    for {
        select {
        case <-stopChan:
            log.Printf("[Attacher] Stopping Redis event reading loop")
            return
        default:
        }

        record, err := reader.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) {
                log.Printf("[Attacher] Redis ring buffer closed")
                return
            }
            log.Printf("[Attacher] Failed to read Redis event: %v", err)
            continue
        }

        if err := processRedisEvent(record.RawSample); err != nil {
            log.Printf("[Attacher] Failed to process Redis event: %v", err)
        }
    }
}

// readICMPEvents continuously reads ICMP events from the ring buffer until stopped.
func readICMPEvents(reader *ringbuf.Reader, stopChan <-chan struct{}) {
    log.Printf("[Attacher] Starting ICMP event reading loop")

    for {
        select {
        case <-stopChan:
            log.Printf("[Attacher] Stopping ICMP event reading loop")
            return
        default:
        }

        record, err := reader.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) {
                log.Printf("[Attacher] ICMP ring buffer closed")
                return
            }
            log.Printf("[Attacher] Failed to read ICMP event: %v", err)
            continue
        }

        if err := processICMPEvent(record.RawSample); err != nil {
            log.Printf("[Attacher] Failed to process ICMP event: %v", err)
        }
    }
}

// readKafkaEvents continuously reads Kafka events from the ring buffer until stopped.
func readKafkaEvents(reader *ringbuf.Reader, stopChan <-chan struct{}) {
    log.Printf("[Attacher] Starting Kafka event reading loop")

    for {
        select {
        case <-stopChan:
            log.Printf("[Attacher] Stopping Kafka event reading loop")
            return
        default:
        }

        record, err := reader.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) {
                log.Printf("[Attacher] Kafka ring buffer closed")
                return
            }
            log.Printf("[Attacher] Failed to read Kafka event: %v", err)
            continue
        }

        if err := processKafkaEvent(record.RawSample); err != nil {
            log.Printf("[Attacher] Failed to process Kafka event: %v", err)
        }
    }
}
