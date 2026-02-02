// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package mixer

import (
    "fmt"
    "log"
    "sync"
    "time"

    "cnFlow/manager/mixer/geoip"
    "cnFlow/protobuf"
)





// FlowMetrics stores performance metrics per network flow.
type FlowMetrics struct {
    FlowKey        string          // srcIP:srcPort->dstIP:dstPort
    FirstSeen      time.Time
    LastSeen       time.Time
    PacketCount    int64
    ByteCount      int64
    PacketTimestamps []time.Time   // Store timestamps of all packets

    Throughput     float64
    Bandwidth      float64
    RTT            []time.Duration
    Jitter         time.Duration
    PacketLoss     float64
    ProtocolStats  map[string]int64

    // GeoIP metrics (GeoDistance removed)
    IsInternational bool
    SourceCountry   string
    DestCountry     string
    TimezoneOffset  string
    SourceISP       string
    DestISP         string

    mu sync.RWMutex
}

// MetricsCalculator manages metrics for all flows.
type MetricsCalculator struct {
    flows map[string]*FlowMetrics
    mu    sync.RWMutex

    // Global statistics
    TotalPackets int64
    TotalBytes   int64
    StartTime    time.Time

    // Geographic statistics
    InternationalFlows int64
    DomesticFlows      int64
    CountryStats       map[string]*CountryFlowStats
}

// CountryFlowStats stores per-country flow statistics.
type CountryFlowStats struct {
    TotalFlows   int64
    TotalBytes   int64
    AvgRTT       time.Duration
    AvgBandwidth float64
}

var GlobalMetrics *MetricsCalculator

// init initializes the global metrics calculator.
func init() {
    GlobalMetrics = &MetricsCalculator{
        flows:        make(map[string]*FlowMetrics),
        StartTime:    time.Now(),
        CountryStats: make(map[string]*CountryFlowStats),
    }
}





// UpdateFlow updates flow metrics based on BaseNetworkEvent.
func (mc *MetricsCalculator) UpdateFlow(base *protobuf.BaseNetworkEvent) *FlowMetrics {
    if mc == nil || base == nil {
        return nil
    }

    flowKey := fmt.Sprintf("%s:%d->%s:%d",
        ipToStr(base.SrcAddr), base.SrcPort,
        ipToStr(base.DstAddr), base.DstPort)

    mc.mu.Lock()
    defer mc.mu.Unlock()

    flow, exists := mc.flows[flowKey]
    if !exists {
        flow = &FlowMetrics{
            FlowKey:       flowKey,
            FirstSeen:     parseTimestamp(base.TimestampNs),
            PacketTimestamps: make([]time.Time, 0),
            ProtocolStats: make(map[string]int64),
        }
        mc.flows[flowKey] = flow
        flow.initializeGeoMetrics(base)
    }

    flow.mu.Lock()
    defer flow.mu.Unlock()

    now := parseTimestamp(base.TimestampNs)
    flow.LastSeen = now
    flow.PacketCount++
    flow.ByteCount += int64(base.PayloadSize)

    // Store packet timestamp
    flow.PacketTimestamps = append(flow.PacketTimestamps, now)
    if len(flow.PacketTimestamps) > 100 {
        flow.PacketTimestamps = flow.PacketTimestamps[len(flow.PacketTimestamps)-50:]
    }

    mc.TotalPackets++
    mc.TotalBytes += int64(base.PayloadSize)

    if flow.IsInternational {
        mc.InternationalFlows++
    } else {
        mc.DomesticFlows++
    }

    flow.calculateMetrics()
    mc.updateCountryStats(flow)

    return flow
}





// UpdateProtocolStats increments the protocol counter for a given flow.
func (mc *MetricsCalculator) UpdateProtocolStats(flowKey, protocol string) {
    mc.mu.RLock()
    flow, ok := mc.flows[flowKey]
    mc.mu.RUnlock()
    if !ok {
        return
    }

    flow.mu.Lock()
    flow.ProtocolStats[protocol]++
    flow.mu.Unlock()
}





// initializeGeoMetrics performs initial GeoIP lookups for a new flow.
func (f *FlowMetrics) initializeGeoMetrics(base *protobuf.BaseNetworkEvent) {
    srcIP := ipToStr(base.SrcAddr)
    dstIP := ipToStr(base.DstAddr)

    srcGeo := geoip.LookupIP(srcIP)
    dstGeo := geoip.LookupIP(dstIP)

    if srcGeo != nil {
        f.SourceCountry = srcGeo.Country
        f.SourceISP = srcGeo.Isp
    }
    if dstGeo != nil {
        f.DestCountry = dstGeo.Country
        f.DestISP = dstGeo.Isp
    }

    if f.SourceCountry != "" && f.DestCountry != "" {
        f.IsInternational = f.SourceCountry != f.DestCountry
    }

    if srcGeo != nil && dstGeo != nil {
        f.TimezoneOffset = geoip.GetTimezoneOffset(srcGeo, dstGeo)
    }
}





// updateCountryStats updates per-country flow statistics from a flow.
func (mc *MetricsCalculator) updateCountryStats(flow *FlowMetrics) {
    if flow.SourceCountry == "" {
        return
    }

    // Initialize CountryStats map if nil
    if mc.CountryStats == nil {
        mc.CountryStats = make(map[string]*CountryFlowStats)
    }

    stats, exists := mc.CountryStats[flow.SourceCountry]
    if !exists {
        stats = &CountryFlowStats{}
        mc.CountryStats[flow.SourceCountry] = stats
    }

    stats.TotalFlows++
    stats.TotalBytes += flow.ByteCount

    if avg := flow.GetAverageRTT(); avg > 0 {
        if stats.AvgRTT == 0 {
            stats.AvgRTT = avg
        } else {
            stats.AvgRTT = (stats.AvgRTT + avg) / 2
        }
    }

    if stats.AvgBandwidth == 0 {
        stats.AvgBandwidth = flow.Bandwidth
    } else {
        stats.AvgBandwidth = (stats.AvgBandwidth + flow.Bandwidth) / 2
    }
}





// calculateMetrics computes throughput, bandwidth, and RTT for the flow.
func (f *FlowMetrics) calculateMetrics() {
    if f.PacketCount >= 2 && f.LastSeen.After(f.FirstSeen) {
        dur := f.LastSeen.Sub(f.FirstSeen)
        if dur > 0 {
            f.Throughput = float64(f.PacketCount) / dur.Seconds()
            f.Bandwidth = float64(f.ByteCount) / dur.Seconds()

            // Simple RTT estimation: average interval between packets
            avgInterval := dur / time.Duration(f.PacketCount-1)
            f.RTT = []time.Duration{avgInterval}

            log.Printf("[Metrics] Flow %s: Duration=%v, Throughput=%.2f pps, Bandwidth=%.2f bps", 
                f.FlowKey, dur, f.Throughput, f.Bandwidth)
        }
    } else {
        log.Printf("[Metrics] Flow %s: Insufficient data - PacketCount=%d", 
            f.FlowKey, f.PacketCount)
    }

    // Calculate jitter (approximate variation in intervals)
    if f.PacketCount > 2 {
        f.calculateSimpleJitter()
    }
}

// calculateSimpleJitter estimates jitter from packet interval variation.
func (f *FlowMetrics) calculateSimpleJitter() {
    if f.PacketCount <= 2 {
        return
    }

    totalDuration := f.LastSeen.Sub(f.FirstSeen)
    expectedInterval := totalDuration / time.Duration(f.PacketCount-1)

    // Simple jitter estimation
    f.Jitter = expectedInterval / 10
}





// GetAverageRTT returns the average round-trip time across all RTT samples.
func (f *FlowMetrics) GetAverageRTT() time.Duration {
    if len(f.RTT) == 0 {
        return 0
    }
    var s time.Duration
    for _, r := range f.RTT {
        s += r
    }
    return s / time.Duration(len(f.RTT))
}

// GetMinRTT returns the minimum round-trip time from all RTT samples.
func (f *FlowMetrics) GetMinRTT() time.Duration {
    if len(f.RTT) == 0 {
        return 0
    }
    min := f.RTT[0]
    for _, r := range f.RTT {
        if r < min {
            min = r
        }
    }
    return min
}

// GetMaxRTT returns the maximum round-trip time from all RTT samples.
func (f *FlowMetrics) GetMaxRTT() time.Duration {
    if len(f.RTT) == 0 {
        return 0
    }
    max := f.RTT[0]
    for _, r := range f.RTT {
        if r > max {
            max = r
        }
    }
    return max
}





// GetMetricsSummary returns all flow metrics as a summary map.
func (f *FlowMetrics) GetMetricsSummary() map[string]interface{} {
    f.mu.RLock()
    defer f.mu.RUnlock()

    return map[string]interface{}{
        "flow_key":         f.FlowKey,
        "duration":         f.LastSeen.Sub(f.FirstSeen),
        "packet_count":     f.PacketCount,
        "byte_count":       f.ByteCount,
        "throughput_pps":   f.Throughput,
        "bandwidth_bps":    f.Bandwidth,
        "avg_rtt":          f.GetAverageRTT(),
        "min_rtt":          f.GetMinRTT(),
        "max_rtt":          f.GetMaxRTT(),
        "jitter":           f.Jitter,
        "packet_loss":      f.PacketLoss,
        "rtt_samples":      len(f.RTT),
        "protocol_stats":   f.ProtocolStats,
        "is_international": f.IsInternational,
        "source_country":   f.SourceCountry,
        "dest_country":     f.DestCountry,
        "timezone_offset":  f.TimezoneOffset,
        "source_isp":       f.SourceISP,
        "dest_isp":         f.DestISP,
    }
}





// GetGlobalStats returns global metrics including total flows, packets, and bandwidth.
func (mc *MetricsCalculator) GetGlobalStats() map[string]interface{} {
    mc.mu.RLock()
    defer mc.mu.RUnlock()

    up := time.Since(mc.StartTime)
    stats := map[string]interface{}{
        "total_flows":         len(mc.flows),
        "total_packets":       mc.TotalPackets,
        "total_bytes":         mc.TotalBytes,
        "uptime":              up,
        "start_time":          mc.StartTime,
        "international_flows": mc.InternationalFlows,
        "domestic_flows":      mc.DomesticFlows,
        "total_countries":     len(mc.CountryStats),
    }
    if up.Seconds() > 0 {
        stats["global_throughput_pps"] = float64(mc.TotalPackets) / up.Seconds()
        stats["global_bandwidth_bps"]  = float64(mc.TotalBytes)   / up.Seconds()
    }
    t := mc.InternationalFlows + mc.DomesticFlows
    if t > 0 {
        stats["international_ratio"] = float64(mc.InternationalFlows) / float64(t) * 100
    }
    return stats
}



// CleanupExpiredFlows removes flows that have not been seen within the given max age.
func (mc *MetricsCalculator) CleanupExpiredFlows(maxAge time.Duration) int {
    mc.mu.Lock()
    defer mc.mu.Unlock()

    now := time.Now()
    var expired []string
    for k, f := range mc.flows {
        f.mu.RLock()
        last := f.LastSeen
        f.mu.RUnlock()
        if now.Sub(last) > maxAge {
            expired = append(expired, k)
        }
    }
    for _, k := range expired {
        delete(mc.flows, k)
    }
    if n := len(expired); n > 0 {
        log.Printf("[Metrics] Cleaned up %d expired flows", n)
    }
    return len(expired)
}

// GetHealthStatus returns the health status of the metrics calculator.
func (mc *MetricsCalculator) GetHealthStatus() map[string]interface{} {
    mc.mu.RLock()
    defer mc.mu.RUnlock()
    return map[string]interface{}{
        "healthy":        true,
        "active_flows":   len(mc.flows),
        "international":  mc.InternationalFlows,
        "domestic":       mc.DomesticFlows,
        "countries_seen": len(mc.CountryStats),
    }
}





// FormatBandwidth formats bits per second into a human-readable string.
func FormatBandwidth(bps float64) string {
    switch {
    case bps >= 1e9:
        return fmt.Sprintf("%.2f Gbps", bps/1e9)
    case bps >= 1e6:
        return fmt.Sprintf("%.2f Mbps", bps/1e6)
    case bps >= 1e3:
        return fmt.Sprintf("%.2f Kbps", bps/1e3)
    default:
        return fmt.Sprintf("%.2f bps", bps)
    }
}

// FormatThroughput formats packets per second into a human-readable string.
func FormatThroughput(pps float64) string {
    switch {
    case pps >= 1e6:
        return fmt.Sprintf("%.2f Mpps", pps/1e6)
    case pps >= 1e3:
        return fmt.Sprintf("%.2f Kpps", pps/1e3)
    default:
        return fmt.Sprintf("%.2f pps", pps)
    }
}
