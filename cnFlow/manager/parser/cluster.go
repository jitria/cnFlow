// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package parser

import (
    "fmt"
    "log"
    "sort"
    "strings"
    "sync"
    "time"

    "cnFlow/manager/mixer"
    "cnFlow/manager/parser/protocol"
)

type ClusterMonitor struct {
    clusterName string

    latencies []time.Duration
    throughputSamples []float64
    protocolThroughput map[string]float64

    httpStats *ProtocolStats
    http2Stats *ProtocolStats
    icmpStats *ICMPStats

    internalTraffic *TrafficFlowStats
    inboundTraffic  *TrafficFlowStats
    outboundTraffic *TrafficFlowStats

    domesticTraffic *GeoTrafficStats
    internationalTraffic *GeoTrafficStats

    seenPods map[string]*PodTrackingInfo
    totalPods int
    privilegedPods int
    hostNetworkPods int

    lastReset time.Time

    mu sync.RWMutex
    ticker *time.Ticker
    stopChan chan struct{}
}

type ProtocolStats struct {
    FlowCount int
    SuccessCount int
    LatencySamples []time.Duration
}

type ICMPStats struct {
    PingCount int
    LossCount int
    RTTSamples []time.Duration
}

type TrafficFlowStats struct {
    FlowCount int
    VolumePps float64
    LatencySamples []time.Duration
    SuccessCount int
}

type GeoTrafficStats struct {
    VolumePps float64
    LatencySamples []time.Duration
}

type PodTrackingInfo struct {
    Name string
    Namespace string
    IsPrivileged bool
    UsesHostNetwork bool
    LastSeen time.Time
}

var GlobalClusterMonitor *ClusterMonitor

// InitClusterMonitor initializes the cluster monitor for the given cluster name.
func InitClusterMonitor(clusterName string) {
    GlobalClusterMonitor = &ClusterMonitor{
        clusterName: clusterName,
        protocolThroughput: make(map[string]float64),
        httpStats: &ProtocolStats{},
        http2Stats: &ProtocolStats{},
        icmpStats: &ICMPStats{},
        internalTraffic: &TrafficFlowStats{},
        inboundTraffic: &TrafficFlowStats{},
        outboundTraffic: &TrafficFlowStats{},
        domesticTraffic: &GeoTrafficStats{},
        internationalTraffic: &GeoTrafficStats{},
        seenPods: make(map[string]*PodTrackingInfo),
        ticker: time.NewTicker(5 * time.Second),
        stopChan: make(chan struct{}),
    }
    
    go GlobalClusterMonitor.loop()
    log.Printf("[ClusterMonitor] Started for cluster: %s (interval 5s)", clusterName)
}

// loop runs the periodic cluster status printing loop.
func (cm *ClusterMonitor) loop() {
    for {
        select {
        case <-cm.ticker.C:
            cm.printClusterStatus()
        case <-cm.stopChan:
            cm.ticker.Stop()
            return
        }
    }
}

// StopClusterMonitor stops the cluster monitor.
func StopClusterMonitor() {
    if GlobalClusterMonitor != nil {
        close(GlobalClusterMonitor.stopChan)
        log.Printf("[ClusterMonitor] Stopped")
    }
}

// ProcessHTTPEvent processes HTTP events and updates cluster metrics.
func (cm *ClusterMonitor) ProcessHTTPEvent(ctx *mixer.EnrichedFlowContext, httpAnalysis *protocol.HTTPAnalysisResult) {
    if cm == nil || ctx == nil {
        return
    }

    cm.mu.Lock()
    defer cm.mu.Unlock()

    cm.updateNetworkHealth(ctx)

    cm.httpStats.FlowCount++
    if httpAnalysis != nil && httpAnalysis.ResponseAnalysis != nil {
        if httpAnalysis.ResponseAnalysis.StatusNumber >= 200 && httpAnalysis.ResponseAnalysis.StatusNumber < 400 {
            cm.httpStats.SuccessCount++
        }
    }
    if len(ctx.Metrics.RTT) > 0 {
        cm.httpStats.LatencySamples = append(cm.httpStats.LatencySamples, ctx.Metrics.RTT[0])
        if len(cm.httpStats.LatencySamples) > 100 {
            cm.httpStats.LatencySamples = cm.httpStats.LatencySamples[len(cm.httpStats.LatencySamples)-50:]
        }
    }

    cm.protocolThroughput["HTTP/1.1"] = ctx.Metrics.Throughput

    cm.updateTrafficFlowClassification(ctx, "HTTP/1.1")

    cm.updateGeographicDistribution(ctx)

    cm.updateSecurityOverview(ctx)
}

// ProcessHTTP2Event processes HTTP/2 events and updates cluster metrics.
func (cm *ClusterMonitor) ProcessHTTP2Event(ctx *mixer.EnrichedFlowContext, http2Analysis *protocol.HTTP2AnalysisResult) {
    if cm == nil || ctx == nil {
        return
    }

    cm.mu.Lock()
    defer cm.mu.Unlock()

    cm.updateNetworkHealth(ctx)

    cm.http2Stats.FlowCount++
    if http2Analysis != nil && http2Analysis.HeadersAnalysis != nil && http2Analysis.HeadersAnalysis.Status != "" {
        statusCode := http2Analysis.HeadersAnalysis.Status
        if strings.HasPrefix(statusCode, "2") || strings.HasPrefix(statusCode, "3") {
            cm.http2Stats.SuccessCount++
        }
    }
    if len(ctx.Metrics.RTT) > 0 {
        cm.http2Stats.LatencySamples = append(cm.http2Stats.LatencySamples, ctx.Metrics.RTT[0])
        if len(cm.http2Stats.LatencySamples) > 100 {
            cm.http2Stats.LatencySamples = cm.http2Stats.LatencySamples[len(cm.http2Stats.LatencySamples)-50:]
        }
    }

    cm.protocolThroughput["HTTP/2"] = ctx.Metrics.Throughput

    cm.updateTrafficFlowClassification(ctx, "HTTP/2")

    cm.updateGeographicDistribution(ctx)

    cm.updateSecurityOverview(ctx)
}

// ProcessICMPEvent processes ICMP events and updates cluster metrics.
func (cm *ClusterMonitor) ProcessICMPEvent(ctx *mixer.EnrichedFlowContext, icmpAnalysis *protocol.ICMPAnalysisResult) {
    if cm == nil || ctx == nil {
        return
    }

    cm.mu.Lock()
    defer cm.mu.Unlock()

    cm.updateNetworkHealth(ctx)

    cm.icmpStats.PingCount++
    if icmpAnalysis != nil && icmpAnalysis.Type == 0 {
        // Success case
    } else if icmpAnalysis != nil && icmpAnalysis.Type == 3 {
        cm.icmpStats.LossCount++
    }
    if len(ctx.Metrics.RTT) > 0 {
        cm.icmpStats.RTTSamples = append(cm.icmpStats.RTTSamples, ctx.Metrics.RTT[0])
        if len(cm.icmpStats.RTTSamples) > 100 {
            cm.icmpStats.RTTSamples = cm.icmpStats.RTTSamples[len(cm.icmpStats.RTTSamples)-50:]
        }
    }

    cm.protocolThroughput["ICMP"] = ctx.Metrics.Throughput

    cm.updateTrafficFlowClassification(ctx, "ICMP")

    cm.updateGeographicDistribution(ctx)

    cm.updateSecurityOverview(ctx)
}

// updateNetworkHealth updates network health metrics.
func (cm *ClusterMonitor) updateNetworkHealth(ctx *mixer.EnrichedFlowContext) {
    if len(ctx.Metrics.RTT) > 0 {
        cm.latencies = append(cm.latencies, ctx.Metrics.RTT[0])
        if len(cm.latencies) > 1000 {
            cm.latencies = cm.latencies[len(cm.latencies)-500:]
        }
    }

    cm.throughputSamples = append(cm.throughputSamples, ctx.Metrics.Throughput)
    if len(cm.throughputSamples) > 1000 {
        cm.throughputSamples = cm.throughputSamples[len(cm.throughputSamples)-500:]
    }
}

// updateTrafficFlowClassification updates traffic flow classification metrics.
func (cm *ClusterMonitor) updateTrafficFlowClassification(ctx *mixer.EnrichedFlowContext, protocol string) {
    srcExternal := ctx.SrcPod == nil
    dstExternal := ctx.DstPod == nil

    var targetStats *TrafficFlowStats

    if !srcExternal && !dstExternal {
        targetStats = cm.internalTraffic
    } else if srcExternal && !dstExternal {
        targetStats = cm.inboundTraffic
    } else if !srcExternal && dstExternal {
        targetStats = cm.outboundTraffic
    } else {
        return
    }

    targetStats.FlowCount++

    if targetStats.VolumePps == 0 {
        targetStats.VolumePps = ctx.Metrics.Throughput
    } else {
        targetStats.VolumePps = (targetStats.VolumePps + ctx.Metrics.Throughput) / 2
    }

    if len(ctx.Metrics.RTT) > 0 {
        targetStats.LatencySamples = append(targetStats.LatencySamples, ctx.Metrics.RTT[0])
        if len(targetStats.LatencySamples) > 100 {
            targetStats.LatencySamples = targetStats.LatencySamples[len(targetStats.LatencySamples)-50:]
        }
    }

    targetStats.SuccessCount++
}

// updateGeographicDistribution updates geographic distribution metrics.
func (cm *ClusterMonitor) updateGeographicDistribution(ctx *mixer.EnrichedFlowContext) {
    if ctx.GeoContext == nil {
        return
    }

    if ctx.GeoContext.IsInternational {
        if cm.internationalTraffic.VolumePps == 0 {
            cm.internationalTraffic.VolumePps = ctx.Metrics.Throughput
        } else {
            cm.internationalTraffic.VolumePps = (cm.internationalTraffic.VolumePps + ctx.Metrics.Throughput) / 2
        }

        if len(ctx.Metrics.RTT) > 0 {
            cm.internationalTraffic.LatencySamples = append(cm.internationalTraffic.LatencySamples, ctx.Metrics.RTT[0])
            if len(cm.internationalTraffic.LatencySamples) > 100 {
                cm.internationalTraffic.LatencySamples = cm.internationalTraffic.LatencySamples[len(cm.internationalTraffic.LatencySamples)-50:]
            }
        }
    } else {
        if cm.domesticTraffic.VolumePps == 0 {
            cm.domesticTraffic.VolumePps = ctx.Metrics.Throughput
        } else {
            cm.domesticTraffic.VolumePps = (cm.domesticTraffic.VolumePps + ctx.Metrics.Throughput) / 2
        }

        if len(ctx.Metrics.RTT) > 0 {
            cm.domesticTraffic.LatencySamples = append(cm.domesticTraffic.LatencySamples, ctx.Metrics.RTT[0])
            if len(cm.domesticTraffic.LatencySamples) > 100 {
                cm.domesticTraffic.LatencySamples = cm.domesticTraffic.LatencySamples[len(cm.domesticTraffic.LatencySamples)-50:]
            }
        }
    }
}

// updateSecurityOverview updates security overview metrics.
func (cm *ClusterMonitor) updateSecurityOverview(ctx *mixer.EnrichedFlowContext) {
    if ctx.SrcPod != nil {
        podKey := fmt.Sprintf("%s/%s", ctx.SrcPod.Namespace, ctx.SrcPod.Name)
        now := time.Now()

        if existing, exists := cm.seenPods[podKey]; exists {
            existing.LastSeen = now
        } else {
            isPrivileged := false
            if ctx.SecurityContext != nil {
                if src, ok := ctx.SecurityContext["source"].(map[string]interface{}); ok {
                    if privileged, ok := src["privileged_mode"].(bool); ok {
                        isPrivileged = privileged
                    }
                }
            }

            cm.seenPods[podKey] = &PodTrackingInfo{
                Name: ctx.SrcPod.Name,
                Namespace: ctx.SrcPod.Namespace,
                IsPrivileged: isPrivileged,
                UsesHostNetwork: ctx.SrcPod.HostNetwork,
                LastSeen: now,
            }

            cm.totalPods++
            if isPrivileged {
                cm.privilegedPods++
            }
            if ctx.SrcPod.HostNetwork {
                cm.hostNetworkPods++
            }
        }
    }
}

// cleanupExpiredPods removes expired pods from the tracking list.
func (cm *ClusterMonitor) cleanupExpiredPods() {
    now := time.Now()
    expireTime := 10 * time.Minute

    for podKey, podInfo := range cm.seenPods {
        if now.Sub(podInfo.LastSeen) > expireTime {
            if podInfo.IsPrivileged {
                cm.privilegedPods--
            }
            if podInfo.UsesHostNetwork {
                cm.hostNetworkPods--
            }
            cm.totalPods--

            delete(cm.seenPods, podKey)
        }
    }

    if cm.totalPods < 0 {
        cm.totalPods = 0
    }
    if cm.privilegedPods < 0 {
        cm.privilegedPods = 0
    }
    if cm.hostNetworkPods < 0 {
        cm.hostNetworkPods = 0
    }
}

// calculateAverage calculates the average latency from samples.
func calculateAverage(samples []time.Duration) float64 {
    if len(samples) == 0 {
        return 0
    }

    var sum time.Duration
    for _, sample := range samples {
        sum += sample
    }

    return float64(sum.Nanoseconds()) / float64(len(samples)) / 1000000
}

// calculateP95 calculates the 95th percentile latency from samples.
func calculateP95(samples []time.Duration) float64 {
    if len(samples) == 0 {
        return 0
    }

    sorted := make([]time.Duration, len(samples))
    copy(sorted, samples)
    sort.Slice(sorted, func(i, j int) bool {
        return sorted[i] < sorted[j]
    })

    index := int(float64(len(sorted)) * 0.95)
    if index >= len(sorted) {
        index = len(sorted) - 1
    }

    return float64(sorted[index].Nanoseconds()) / 1000000
}

// calculateThroughputAverage calculates the average throughput from samples.
func calculateThroughputAverage(samples []float64) float64 {
    if len(samples) == 0 {
        return 0
    }

    var sum float64
    for _, sample := range samples {
        sum += sample
    }

    return sum / float64(len(samples))
}

// calculateSuccessRate calculates the success rate as a percentage.
func calculateSuccessRate(successCount, totalCount int) float64 {
    if totalCount == 0 {
        return 0
    }
    return float64(successCount) / float64(totalCount) * 100
}

// calculateLossRate calculates the loss rate as a percentage.
func calculateLossRate(lossCount, totalCount int) float64 {
    if totalCount == 0 {
        return 0
    }
    return float64(lossCount) / float64(totalCount) * 100
}

// calculatePercentage calculates a percentage.
func calculatePercentage(count, total int) float64 {
    if total == 0 {
        return 0
    }
    return float64(count) / float64(total) * 100
}

// printClusterStatus prints the current cluster status.
func (cm *ClusterMonitor) printClusterStatus() {
    cm.mu.RLock()
    defer cm.mu.RUnlock()

    now := time.Now()
    if cm.lastReset.IsZero() || now.Sub(cm.lastReset) > 10*time.Minute {
        cm.cleanupExpiredPods()
        cm.lastReset = now
    }

    log.Println("==================== CLUSTER STATUS ====================")
    log.Printf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))

    log.Printf("Cluster: %s", cm.clusterName)
    log.Println()

    log.Println("Protocol Distribution                    │ Traffic Flow Analysis")
    log.Println("─────────────────────────────────────────┼─────────────────────────────────────────")

    http1SuccessRate := calculateSuccessRate(cm.httpStats.SuccessCount, cm.httpStats.FlowCount)
    http1AvgLatency := calculateAverage(cm.httpStats.LatencySamples)
    internalLatency := calculateAverage(cm.internalTraffic.LatencySamples)

    log.Printf("HTTP/1.1: %d flows (%.1f%%, %.2fms)      │ Internal (Pod↔Pod): %d flows (%.2fms avg)",
        cm.httpStats.FlowCount, http1SuccessRate, http1AvgLatency,
        cm.internalTraffic.FlowCount, internalLatency)

    http2SuccessRate := calculateSuccessRate(cm.http2Stats.SuccessCount, cm.http2Stats.FlowCount)
    http2AvgLatency := calculateAverage(cm.http2Stats.LatencySamples)
    inboundLatency := calculateAverage(cm.inboundTraffic.LatencySamples)

    log.Printf("HTTP/2: %d flows (%.1f%%, %.2fms)         │ Inbound (External→Pod): %d flows (%.2fms avg)",
        cm.http2Stats.FlowCount, http2SuccessRate, http2AvgLatency,
        cm.inboundTraffic.FlowCount, inboundLatency)

    icmpLossRate := calculateLossRate(cm.icmpStats.LossCount, cm.icmpStats.PingCount)
    icmpAvgRTT := calculateAverage(cm.icmpStats.RTTSamples)
    outboundLatency := calculateAverage(cm.outboundTraffic.LatencySamples)

    log.Printf("ICMP: %d pings (%.1f%%, %.2fms)          │ Outbound (Pod→External): %d flows (%.2fms avg)",
        cm.icmpStats.PingCount, icmpLossRate, icmpAvgRTT,
        cm.outboundTraffic.FlowCount, outboundLatency)

    log.Println()

    log.Println("Geographic Distribution                  │ Security Overview")
    log.Println("─────────────────────────────────────────┼─────────────────────────────────────────")

    totalGeoVolume := cm.domesticTraffic.VolumePps + cm.internationalTraffic.VolumePps
    if totalGeoVolume > 0 && cm.totalPods > 0 {
        domesticPercentage := cm.domesticTraffic.VolumePps / totalGeoVolume * 100
        internationalPercentage := cm.internationalTraffic.VolumePps / totalGeoVolume * 100

        domesticAvgLatency := calculateAverage(cm.domesticTraffic.LatencySamples)
        internationalAvgLatency := calculateAverage(cm.internationalTraffic.LatencySamples)

        privilegedPercentage := calculatePercentage(cm.privilegedPods, cm.totalPods)
        hostNetworkPercentage := calculatePercentage(cm.hostNetworkPods, cm.totalPods)

        log.Printf("Domestic: %.1f%% (%.2fms avg)           │ Active Pods: %d pods",
            domesticPercentage, domesticAvgLatency, cm.totalPods)
        log.Printf("International: %.1f%% (%.2fms avg)      │ Privileged: %d pods (%.1f%%)",
            internationalPercentage, internationalAvgLatency, cm.privilegedPods, privilegedPercentage)
        log.Printf("                                         │ Host Network: %d pods (%.1f%%)",
            cm.hostNetworkPods, hostNetworkPercentage)

        if privilegedPercentage > 20.0 {
            log.Printf("                                         │ [ALERT] High privileged pod ratio!")
        }
        if icmpLossRate > 5.0 {
            log.Printf("                                         │ [ALERT] High ICMP loss rate!")
        }
    } else if cm.totalPods > 0 {
        privilegedPercentage := calculatePercentage(cm.privilegedPods, cm.totalPods)
        hostNetworkPercentage := calculatePercentage(cm.hostNetworkPods, cm.totalPods)

        log.Printf("(no geographic data)                     │ Active Pods: %d pods", cm.totalPods)
        log.Printf("                                         │ Privileged: %d pods (%.1f%%)",
            cm.privilegedPods, privilegedPercentage)
        log.Printf("                                         │ Host Network: %d pods (%.1f%%)",
            cm.hostNetworkPods, hostNetworkPercentage)
    } else {
        log.Printf("(no geographic data)                     │ (no active pods)")
    }

    log.Println("=========================================================")
}
