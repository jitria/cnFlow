// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package parser

import (
    "log"
    "sync"
    "encoding/json"

    "cnFlow/protobuf"
    "cnFlow/manager/parser/protocol"
    "cnFlow/manager/mixer"
)

type parserHandler struct {
    waitGroup *sync.WaitGroup
    stopChan  chan struct{}
}

var ParserH *parserHandler

// InitParserHandler initializes the parser handler with the given stop channel.
func InitParserHandler(stopChan chan struct{}) error {
    ParserH = &parserHandler{
        stopChan:  stopChan,
        waitGroup: new(sync.WaitGroup),
    }

    InitNamespaceMonitor()

    InitClusterMonitor("ICTC cluster")
    
    log.Printf("[ParserH] Parser handler initialized")
    return nil
}

// StartParserHandler starts the parser handler in a goroutine.
func StartParserHandler() error {
    ParserH.waitGroup.Add(1)
    go func() {
        defer ParserH.waitGroup.Done()
        log.Printf("[ParserH] Parser handler started")
        
        <-ParserH.stopChan
        log.Printf("[ParserH] Parser handler stopping")
    }()
    
    return nil
}

// WaitShutdown waits for all parser goroutines to finish.
func WaitShutdown() {
    ParserH.waitGroup.Wait()
    log.Printf("[ParserH] All parser goroutines stopped")
}

// ProcessKafkaEvent processes Kafka events and sends them to the namespace monitor.
func ProcessKafkaEvent(event *protobuf.KafkaEvent) {
    enrichedCtx := mixer.AnalyzeEnrichedFlow(event.Base, "Kafka")
    if b, err := json.MarshalIndent(enrichedCtx, "", "  "); err == nil {
        log.Println("[ParserH] EnrichedContext:", string(b))
    }

    kafkaAnalysis := protocol.AnalyzeKafkaEventDetailed(event)
    if b, err := json.MarshalIndent(kafkaAnalysis, "", "  "); err == nil {
        log.Println("[ParserH] KAFKA analysis:", string(b))
    }

    formattedOutput := FormatKafkaEvent(enrichedCtx, kafkaAnalysis)
    log.Printf("[ParserH] Kafka Flow:\n%s", formattedOutput)

    if GlobalNamespaceMonitor != nil {
        GlobalNamespaceMonitor.ProcessKafkaEvent(enrichedCtx, kafkaAnalysis)
    }
}

// ProcessRedisEvent processes Redis events and sends them to the namespace monitor.
func ProcessRedisEvent(event *protobuf.RedisEvent) {
    enrichedCtx := mixer.AnalyzeEnrichedFlow(event.Base, "Redis")
    if b, err := json.MarshalIndent(enrichedCtx, "", "  "); err == nil {
        log.Println("[ParserH] EnrichedContext:", string(b))
    }

    redisAnalysis := protocol.AnalyzeRedisEventDetailed(event)
    if b, err := json.MarshalIndent(redisAnalysis, "", "  "); err == nil {
        log.Println("[ParserH] REDIS analysis:", string(b))
    }

    formattedOutput := FormatRedisEvent(enrichedCtx, redisAnalysis)
    log.Printf("[ParserH] Redis Flow:\n%s", formattedOutput)

    if GlobalNamespaceMonitor != nil {
        GlobalNamespaceMonitor.ProcessRedisEvent(enrichedCtx, redisAnalysis)
    }
}

// ProcessDNSEvent processes DNS events and logs the analysis results.
func ProcessDNSEvent(event *protobuf.DNSEvent) {
    enrichedCtx := mixer.AnalyzeEnrichedFlow(event.Base, "DNS")
    if b, err := json.MarshalIndent(enrichedCtx, "", "  "); err == nil {
        log.Println("[ParserH] EnrichedContext:", string(b))
    }

    dnsAnalysis := protocol.AnalyzeDNSEventDetailed(event)
    if b, err := json.MarshalIndent(dnsAnalysis, "", "  "); err == nil {
        log.Println("[ParserH] DNS analysis:", string(b))
    }

    formattedOutput := FormatDNSEvent(enrichedCtx, dnsAnalysis)
    log.Printf("[ParserH] DNS Flow:\n%s", formattedOutput)

}

// ProcessHTTPEvent processes HTTP events and sends them to the cluster monitor.
func ProcessHTTPEvent(event *protobuf.HTTPEvent) {
    enrichedCtx := mixer.AnalyzeEnrichedFlow(event.Base, "HTTP")
    if b, err := json.MarshalIndent(enrichedCtx, "", "  "); err == nil {
        log.Println("[ParserH] EnrichedContext:", string(b))
    }

    httpAnalysis := protocol.AnalyzeHTTPEventDetailed(event)
    if b, err := json.MarshalIndent(httpAnalysis, "", "  "); err == nil {
        log.Println("[ParserH] HTTP analysis:", string(b))
    }

    formattedOutput := FormatHTTPEvent(enrichedCtx, httpAnalysis)
    log.Printf("[ParserH] HTTP Flow:\n%s", formattedOutput)

    if GlobalClusterMonitor != nil {
        GlobalClusterMonitor.ProcessHTTPEvent(enrichedCtx, httpAnalysis)
    }
}

// ProcessHTTP2Event processes HTTP/2 events and sends them to the cluster monitor.
func ProcessHTTP2Event(event *protobuf.HTTP2Event) {
    enrichedCtx := mixer.AnalyzeEnrichedFlow(event.Base, "HTTP2")
    if b, err := json.MarshalIndent(enrichedCtx, "", "  "); err == nil {
        log.Println("[ParserH] EnrichedContext:", string(b))
    }

    http2Analysis := protocol.AnalyzeHTTP2EventDetailed(event)
    if b, err := json.MarshalIndent(http2Analysis, "", "  "); err == nil {
        log.Println("[ParserH] HTTP2 analysis:", string(b))
    }

    formattedOutput := FormatHTTP2Event(enrichedCtx, http2Analysis)
    log.Printf("[ParserH] HTTP2 Flow:\n%s", formattedOutput)

    if GlobalClusterMonitor != nil {
        GlobalClusterMonitor.ProcessHTTP2Event(enrichedCtx, http2Analysis)
    }
}

// ProcessICMPEvent processes ICMP events and sends them to the cluster monitor.
func ProcessICMPEvent(event *protobuf.ICMPEvent) {
    enrichedCtx := mixer.AnalyzeEnrichedFlow(event.Base, "ICMP")   
    if b, err := json.MarshalIndent(enrichedCtx, "", "  "); err == nil {
        log.Println("[ParserH] EnrichedContext:", string(b))
    }
    
    icmpAnalysis := protocol.AnalyzeICMPEventDetailed(event)
    if b, err := json.MarshalIndent(icmpAnalysis, "", "  "); err == nil {
        log.Println("[ParserH] ICMP analysis:", string(b))
    }

    formattedOutput := FormatICMPEvent(enrichedCtx, icmpAnalysis)
    log.Printf("[ParserH] ICMP Flow:\n%s", formattedOutput)

    if GlobalClusterMonitor != nil {
        GlobalClusterMonitor.ProcessICMPEvent(enrichedCtx, icmpAnalysis)
    }
}