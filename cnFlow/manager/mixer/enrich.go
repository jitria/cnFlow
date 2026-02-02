// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package mixer

import (
    "fmt"
    "log"
    "strings"
    "sync"
    "time"
    "cnFlow/protobuf"
    "cnFlow/manager/mixer/geoip"
)

// DeduplicationManager manages packet deduplication.
type DeduplicationManager struct {
    seenPackets map[string]time.Time
    mu          sync.RWMutex
}

// NewDeduplicationManager creates a new deduplication manager.
func NewDeduplicationManager() *DeduplicationManager {
    return &DeduplicationManager{
        seenPackets: make(map[string]time.Time),
    }
}

// IsDuplicate checks if a packet is a duplicate.
func (dm *DeduplicationManager) IsDuplicate(base *protobuf.BaseNetworkEvent) bool {
    identifier := fmt.Sprintf("%s:%d->%s:%d/%d/%d",
        ipToStr(base.SrcAddr), base.SrcPort,
        ipToStr(base.DstAddr), base.DstPort,
        base.Seq, base.TimestampNs)
    
    dm.mu.Lock()
    defer dm.mu.Unlock()
    
    if lastSeen, exists := dm.seenPackets[identifier]; exists {
        if time.Since(lastSeen) < time.Second {
            return true
        }
    }
    
    dm.seenPackets[identifier] = time.Now()

    // Clean up old entries for memory efficiency
    if len(dm.seenPackets) > 10000 {
        dm.cleanupOldEntries()
    }
    
    return false
}

// cleanupOldEntries cleans up old deduplication entries.
func (dm *DeduplicationManager) cleanupOldEntries() {
    now := time.Now()
    for key, timestamp := range dm.seenPackets {
        if now.Sub(timestamp) > 5*time.Second {
            delete(dm.seenPackets, key)
        }
    }
}

// HTTPTransaction tracks individual HTTP request-response pairs.
type HTTPTransaction struct {
    TransactionID string
    FlowKey       string
    RequestTime   time.Time
    ResponseTime  time.Time
    Method        string
    URI           string
    StatusCode    int
    RequestSeq    uint32
    RTT           time.Duration
    Completed     bool
}

// HTTPTransactionTracker tracks HTTP transactions.
type HTTPTransactionTracker struct {
    transactions map[string]*HTTPTransaction
    mu           sync.RWMutex
}

// NewHTTPTransactionTracker creates a new HTTP transaction tracker.
func NewHTTPTransactionTracker() *HTTPTransactionTracker {
    return &HTTPTransactionTracker{
        transactions: make(map[string]*HTTPTransaction),
    }
}

// ProcessHTTPPacket processes HTTP packets and tracks transactions.
func (htt *HTTPTransactionTracker) ProcessHTTPPacket(base *protobuf.BaseNetworkEvent, isRequest bool, method, uri string, statusCode int) {
    flowKey := fmt.Sprintf("%s:%d->%s:%d",
        ipToStr(base.SrcAddr), base.SrcPort,
        ipToStr(base.DstAddr), base.DstPort)
    
    if isRequest {
        txnID := fmt.Sprintf("%s_%d_%d", flowKey, base.Seq, base.TimestampNs)
        
        htt.mu.Lock()
        htt.transactions[txnID] = &HTTPTransaction{
            TransactionID: txnID,
            FlowKey:       flowKey,
            RequestTime:   parseTimestamp(base.TimestampNs),
            Method:        method,
            URI:           uri,
            RequestSeq:    base.Seq,
            Completed:     false,
        }
        htt.mu.Unlock()
    } else {
        if txn := htt.findMatchingRequest(base, flowKey); txn != nil {
            htt.mu.Lock()
            txn.ResponseTime = parseTimestamp(base.TimestampNs)
            txn.StatusCode = statusCode
            txn.RTT = txn.ResponseTime.Sub(txn.RequestTime)
            txn.Completed = true
            htt.mu.Unlock()
        }
    }
}

// findMatchingRequest finds the matching request for a response.
func (htt *HTTPTransactionTracker) findMatchingRequest(base *protobuf.BaseNetworkEvent, flowKey string) *HTTPTransaction {
    htt.mu.RLock()
    defer htt.mu.RUnlock()
    
    responseTime := parseTimestamp(base.TimestampNs)
    var bestMatch *HTTPTransaction
    var minTimeDiff time.Duration = time.Hour
    
    for _, txn := range htt.transactions {
        if !txn.Completed && txn.FlowKey == flowKey {
            timeDiff := responseTime.Sub(txn.RequestTime)
            if timeDiff > 0 && timeDiff < minTimeDiff {
                bestMatch = txn
                minTimeDiff = timeDiff
            }
        }
    }

    // Match only within reasonable time range
    if minTimeDiff < 30*time.Second {
        return bestMatch
    }
    return nil
}

// GetCompletedTransactions returns completed transactions.
func (htt *HTTPTransactionTracker) GetCompletedTransactions() []*HTTPTransaction {
    htt.mu.Lock()
    defer htt.mu.Unlock()
    
    var completed []*HTTPTransaction
    for key, txn := range htt.transactions {
        if txn.Completed {
            completed = append(completed, txn)
            delete(htt.transactions, key) // Remove completed transaction
        }
    }
    
    return completed
}

var (
    globalDeduplicator    *DeduplicationManager
    globalHTTPTracker     *HTTPTransactionTracker
    initOnce              sync.Once
)

// initGlobalInstances initializes global instances.
func initGlobalInstances() {
    initOnce.Do(func() {
        globalDeduplicator = NewDeduplicationManager()
        globalHTTPTracker = NewHTTPTransactionTracker()
    })
}

// EnrichedFlowContext provides complete network flow context.
type EnrichedFlowContext struct {
    // Basic flow information
    SrcIP, DstIP     string
    SrcPort, DstPort uint32
    Protocol         string

    // Kubernetes metadata
    SrcPod, DstPod   *protobuf.PodInfo
    SrcNode, DstNode *protobuf.NodeInfo

    // Geographic context
    GeoContext       *GeoContext

    // Performance metrics
    Metrics          *FlowMetrics

    // Network topology
    NetworkTopology  map[string]interface{}

    // Security context
    SecurityContext  map[string]interface{}

    // HTTP transaction information
    HTTPTransactions []*HTTPTransaction
}

// GeoContext contains geographic analysis information.
type GeoContext struct {
    SourceGeo      *protobuf.GeoInfo
    DestinationGeo *protobuf.GeoInfo
    IsInternational bool
    TimezoneOffset  string
}

// parseTimestamp safely converts nanosecond timestamp to time.Time.
func parseTimestamp(timestampNs uint64) time.Time {
    if timestampNs == 0 || timestampNs < 1000000000000000000 { // Use current time if before 2001
        return time.Now()
    }
    return time.Unix(0, int64(timestampNs))
}

// AnalyzeEnrichedFlow performs complete context analysis on BaseNetworkEvent.
func AnalyzeEnrichedFlow(base *protobuf.BaseNetworkEvent, protocol string) *EnrichedFlowContext {
    if base == nil {
        return nil
    }

    // Initialize global instances
    initGlobalInstances()

    // Check for duplicate packets
    if globalDeduplicator.IsDuplicate(base) {
        log.Printf("[EnrichFlow] Duplicate packet detected, skipping")
        return nil
    }
    
    srcIP := ipToStr(base.SrcAddr)
    dstIP := ipToStr(base.DstAddr)
    
    ctx := &EnrichedFlowContext{
        SrcIP:    srcIP,
        DstIP:    dstIP,
        SrcPort:  base.SrcPort,
        DstPort:  base.DstPort,
        Protocol: protocol,
    }

    // 1. Retrieve Kubernetes metadata
    ctx.enrichWithK8sMetadata()

    // 2. Perform geographic analysis (with external IP support)
    ctx.enrichWithGeographicData()

    // 3. Update performance metrics
    ctx.enrichWithMetrics(base)

    // 4. Analyze network topology
    ctx.enrichWithNetworkTopology()

    // 5. Analyze security context
    ctx.enrichWithSecurityContext()

    // 6. Track HTTP transactions (for HTTP protocol)
    if protocol == "HTTP" {
        ctx.enrichWithHTTPTransactions()
    }
    
    return ctx
}

// AnalyzeEnrichedFlowWithHTTP performs analysis including HTTP event information.
func AnalyzeEnrichedFlowWithHTTP(base *protobuf.BaseNetworkEvent, protocol string, isRequest bool, method, uri string, statusCode int) *EnrichedFlowContext {
    ctx := AnalyzeEnrichedFlow(base, protocol)
    if ctx == nil {
        return nil
    }

    // Process HTTP transaction
    if protocol == "HTTP" {
        globalHTTPTracker.ProcessHTTPPacket(base, isRequest, method, uri, statusCode)
        ctx.enrichWithHTTPTransactions()
    }
    
    return ctx
}

// enrichWithK8sMetadata populates Kubernetes pod and node metadata for source and destination IPs.
func (ctx *EnrichedFlowContext) enrichWithK8sMetadata() {
    if MixerH == nil || MixerH.k8sMetadata == nil {
        return
    }

    // Retrieve source Pod
    if pod, exists := MixerH.k8sMetadata.GetPodByIP(ctx.SrcIP); exists {
        ctx.SrcPod = pod
        if node, exists := MixerH.k8sMetadata.GetNodeByName(pod.Node); exists {
            ctx.SrcNode = node
        }
    }

    // Retrieve destination Pod
    if pod, exists := MixerH.k8sMetadata.GetPodByIP(ctx.DstIP); exists {
        ctx.DstPod = pod
        if node, exists := MixerH.k8sMetadata.GetNodeByName(pod.Node); exists {
            ctx.DstNode = node
        }
    }
}

// enrichWithGeographicData populates geographic context using node info or GeoIP lookups.
func (ctx *EnrichedFlowContext) enrichWithGeographicData() {
    ctx.GeoContext = &GeoContext{}

    // Retrieve source geographic information
    if ctx.SrcNode != nil && ctx.SrcNode.GeoInfo != nil {
        // Use geographic info from internal cluster node
        ctx.GeoContext.SourceGeo = ctx.SrcNode.GeoInfo
    } else {
        // Perform GeoIP lookup for external IP
        if cachedGeo, found := geoip.GetCachedGeoInfo(ctx.SrcIP); found {
            ctx.GeoContext.SourceGeo = cachedGeo
        } else if geoInfo := geoip.LookupIP(ctx.SrcIP); geoInfo != nil {
            ctx.GeoContext.SourceGeo = geoInfo
            // Store lookup result in cache
            geoip.SetCachedGeoInfo(ctx.SrcIP, geoInfo)
        }
    }

    // Retrieve destination geographic information
    if ctx.DstNode != nil && ctx.DstNode.GeoInfo != nil {
        // Use geographic info from internal cluster node
        ctx.GeoContext.DestinationGeo = ctx.DstNode.GeoInfo
    } else {
        // Perform GeoIP lookup for external IP
        if cachedGeo, found := geoip.GetCachedGeoInfo(ctx.DstIP); found {
            ctx.GeoContext.DestinationGeo = cachedGeo
        } else if geoInfo := geoip.LookupIP(ctx.DstIP); geoInfo != nil {
            ctx.GeoContext.DestinationGeo = geoInfo
            // Store lookup result in cache
            geoip.SetCachedGeoInfo(ctx.DstIP, geoInfo)
        }
    }

    // Check if international communication
    if ctx.GeoContext.SourceGeo != nil && ctx.GeoContext.DestinationGeo != nil {
        ctx.GeoContext.IsInternational = ctx.GeoContext.SourceGeo.Country != ctx.GeoContext.DestinationGeo.Country

        // Analyze timezone difference
        if ctx.GeoContext.SourceGeo.Timezone != ctx.GeoContext.DestinationGeo.Timezone {
            ctx.GeoContext.TimezoneOffset = geoip.GetTimezoneOffset(ctx.GeoContext.SourceGeo, ctx.GeoContext.DestinationGeo)
        }
    }
}

// enrichWithMetrics updates flow performance metrics from the base network event.
func (ctx *EnrichedFlowContext) enrichWithMetrics(base *protobuf.BaseNetworkEvent) {
    if MixerH == nil || MixerH.metricsCalculator == nil {
        return
    }

    // Update flow metrics
    ctx.Metrics = MixerH.metricsCalculator.UpdateFlow(base)

    // Update protocol-specific statistics
    if ctx.Metrics != nil {
        flowKey := fmt.Sprintf("%s:%d->%s:%d", ctx.SrcIP, ctx.SrcPort, ctx.DstIP, ctx.DstPort)
        MixerH.metricsCalculator.UpdateProtocolStats(flowKey, ctx.Protocol)
    }
}

// enrichWithNetworkTopology analyzes and populates network topology information.
func (ctx *EnrichedFlowContext) enrichWithNetworkTopology() {
    if MixerH == nil || MixerH.k8sMetadata == nil {
        return
    }
    
    ctx.NetworkTopology = MixerH.k8sMetadata.AnalyzeNetworkTopology(ctx.SrcPod, ctx.DstPod)
}

// enrichWithSecurityContext populates security context for source and destination pods.
func (ctx *EnrichedFlowContext) enrichWithSecurityContext() {
    if MixerH == nil || MixerH.k8sMetadata == nil {
        return
    }
    
    ctx.SecurityContext = make(map[string]interface{})

    // Source security context
    if ctx.SrcPod != nil {
        srcSecurity := MixerH.k8sMetadata.AnalyzePodSecurity(ctx.SrcPod)
        if srcSecurity != nil {
            ctx.SecurityContext["source"] = srcSecurity
        }
    }

    // Destination security context
    if ctx.DstPod != nil {
        dstSecurity := MixerH.k8sMetadata.AnalyzePodSecurity(ctx.DstPod)
        if dstSecurity != nil {
            ctx.SecurityContext["destination"] = dstSecurity
        }
    }

    // Overall security summary information
    ctx.SecurityContext["security_summary"] = ctx.generateSecuritySummary()
}

// enrichWithHTTPTransactions retrieves completed HTTP transactions from the global tracker.
func (ctx *EnrichedFlowContext) enrichWithHTTPTransactions() {
    if globalHTTPTracker == nil {
        return
    }

    // Retrieve completed HTTP transactions
    ctx.HTTPTransactions = globalHTTPTracker.GetCompletedTransactions()
}

// LogCompleteAnalysis logs complete network flow analysis results.
func (ctx *EnrichedFlowContext) LogCompleteAnalysis() {
    if ctx == nil {
        return
    }
    
    log.Printf("========== %s COMPLETE ENRICHED ANALYSIS ==========", ctx.Protocol)

    // Basic flow information
    ctx.logBasicFlowInfo()

    // Kubernetes context
    ctx.logKubernetesContext()

    // Geographic context (including external IP information)
    ctx.logGeographicContext()

    // Performance metrics
    ctx.logPerformanceMetrics()

    // Network topology
    ctx.logNetworkTopology()

    // Security analysis
    ctx.logSecurityAnalysis()

    // HTTP transaction information
    ctx.logHTTPTransactions()

    // Summary information
    ctx.logSummary()
    
    log.Printf("=====================================================")
}

// logBasicFlowInfo logs basic flow information including protocol, addresses, and direction.
func (ctx *EnrichedFlowContext) logBasicFlowInfo() {
    log.Printf("Basic Flow Information:")
    log.Printf("  Protocol: %s", ctx.Protocol)
    log.Printf("  Flow: %s:%d -> %s:%d", ctx.SrcIP, ctx.SrcPort, ctx.DstIP, ctx.DstPort)
    log.Printf("  Direction: %s", ctx.getFlowDirection())
}

// logKubernetesContext logs Kubernetes pod and namespace context for the flow.
func (ctx *EnrichedFlowContext) logKubernetesContext() {
    log.Printf("Kubernetes Context:")
    
    if ctx.SrcPod != nil && ctx.DstPod != nil {
        log.Printf("  Flow Type: Pod-to-Pod")
        log.Printf("  Source: %s/%s (Node: %s)", ctx.SrcPod.Namespace, ctx.SrcPod.Name, ctx.SrcPod.Node)
        log.Printf("  Destination: %s/%s (Node: %s)", ctx.DstPod.Namespace, ctx.DstPod.Name, ctx.DstPod.Node)
        
        if ctx.SrcPod.Namespace == ctx.DstPod.Namespace {
            log.Printf("  Scope: Intra-namespace (%s)", ctx.SrcPod.Namespace)
        } else {
            log.Printf("  Scope: Cross-namespace (%s -> %s)", ctx.SrcPod.Namespace, ctx.DstPod.Namespace)
        }
        
        // Service Account information
        if ctx.SrcPod.ServiceAccount != nil {
            log.Printf("  Source ServiceAccount: %s/%s",
                ctx.SrcPod.ServiceAccount.Namespace, ctx.SrcPod.ServiceAccount.Name)
        }
        if ctx.DstPod.ServiceAccount != nil {
            log.Printf("  Destination ServiceAccount: %s/%s",
                ctx.DstPod.ServiceAccount.Namespace, ctx.DstPod.ServiceAccount.Name)
        }
        
    } else if ctx.SrcPod != nil {
        log.Printf("  Flow Type: Pod-to-External")
        log.Printf("  Source: %s/%s (Node: %s)", ctx.SrcPod.Namespace, ctx.SrcPod.Name, ctx.SrcPod.Node)
        log.Printf("  Destination: External (%s)", ctx.DstIP)
    } else if ctx.DstPod != nil {
        log.Printf("  Flow Type: External-to-Pod")
        log.Printf("  Source: External (%s)", ctx.SrcIP)
        log.Printf("  Destination: %s/%s (Node: %s)", ctx.DstPod.Namespace, ctx.DstPod.Name, ctx.DstPod.Node)
    } else {
        log.Printf("  Flow Type: External-to-External")
        log.Printf("  Note: Transit traffic through cluster")
    }
}

// logGeographicContext logs geographic information including country, timezone, and ISP details.
func (ctx *EnrichedFlowContext) logGeographicContext() {
    if ctx.GeoContext == nil {
        return
    }
    
    log.Printf("Geographic Context:")
    
    if ctx.GeoContext.SourceGeo != nil && ctx.GeoContext.DestinationGeo != nil {
        if ctx.GeoContext.IsInternational {
            log.Printf("  Type: International communication")
            log.Printf("  Route: %s -> %s", ctx.GeoContext.SourceGeo.Country, ctx.GeoContext.DestinationGeo.Country)
        } else {
            log.Printf("  Type: Domestic communication (%s)", ctx.GeoContext.SourceGeo.Country)
        }
        
        if ctx.GeoContext.TimezoneOffset != "" {
            log.Printf("  Timezone: %s", ctx.GeoContext.TimezoneOffset)
        }
        
        // Detailed location information output
        if ctx.GeoContext.SourceGeo.City != "" || ctx.GeoContext.SourceGeo.Region != "" {
            log.Printf("  Source Location: %s", geoip.FormatLocationString(ctx.GeoContext.SourceGeo))
        }
        if ctx.GeoContext.DestinationGeo.City != "" || ctx.GeoContext.DestinationGeo.Region != "" {
            log.Printf("  Destination Location: %s", geoip.FormatLocationString(ctx.GeoContext.DestinationGeo))
        }
        
        // Coordinate information
        if srcCoords := geoip.GetCoordinatesString(ctx.GeoContext.SourceGeo); srcCoords != "" {
            log.Printf("  Source Coordinates: %s", srcCoords)
        }
        if dstCoords := geoip.GetCoordinatesString(ctx.GeoContext.DestinationGeo); dstCoords != "" {
            log.Printf("  Destination Coordinates: %s", dstCoords)
        }
        
        // ISP information
        if ctx.GeoContext.SourceGeo.Isp != "" {
            log.Printf("  Source ISP: %s (%s)", ctx.GeoContext.SourceGeo.Isp, ctx.GeoContext.SourceGeo.Org)
        }
        if ctx.GeoContext.DestinationGeo.Isp != "" {
            log.Printf("  Destination ISP: %s (%s)", ctx.GeoContext.DestinationGeo.Isp, ctx.GeoContext.DestinationGeo.Org)
        }
        
        // AS information
        if ctx.GeoContext.SourceGeo.AsNumber > 0 {
            log.Printf("  Source AS: %s (AS%d)", ctx.GeoContext.SourceGeo.AsName, ctx.GeoContext.SourceGeo.AsNumber)
        }
        if ctx.GeoContext.DestinationGeo.AsNumber > 0 {
            log.Printf("  Destination AS: %s (AS%d)", ctx.GeoContext.DestinationGeo.AsName, ctx.GeoContext.DestinationGeo.AsNumber)
        }
        
    } else if ctx.GeoContext.SourceGeo != nil {
        log.Printf("  Source Location: %s", geoip.FormatLocationString(ctx.GeoContext.SourceGeo))
        log.Printf("  Destination: Unknown location")
    } else if ctx.GeoContext.DestinationGeo != nil {
        log.Printf("  Source: Unknown location")
        log.Printf("  Destination Location: %s", geoip.FormatLocationString(ctx.GeoContext.DestinationGeo))
    } else {
        log.Printf("  No geographic information available")
    }
}

// logPerformanceMetrics logs performance metrics including throughput, bandwidth, and RTT.
func (ctx *EnrichedFlowContext) logPerformanceMetrics() {
    if ctx.Metrics == nil {
        return
    }
    
    log.Printf("Performance Metrics:")
    
    metrics := ctx.Metrics.GetMetricsSummary()
    
    if duration, ok := metrics["duration"].(time.Duration); ok && duration > 0 {
        log.Printf("  Flow Duration: %v", duration)
    }
    
    if packetCount, ok := metrics["packet_count"].(int64); ok {
        log.Printf("  Total Packets: %d", packetCount)
    }
    
    if byteCount, ok := metrics["byte_count"].(int64); ok {
        log.Printf("  Total Bytes: %d (%s)", byteCount, formatBytes(byteCount))
    }
    
    if throughput, ok := metrics["throughput_pps"].(float64); ok && throughput > 0 {
        log.Printf("  Throughput: %s", FormatThroughput(throughput))
    }
    
    if bandwidth, ok := metrics["bandwidth_bps"].(float64); ok && bandwidth > 0 {
        log.Printf("  Bandwidth: %s", FormatBandwidth(bandwidth))
    }
    
    if avgRTT, ok := metrics["avg_rtt"].(time.Duration); ok && avgRTT > 0 {
        log.Printf("  Average RTT: %v", avgRTT)
    }
    
    if minRTT, ok := metrics["min_rtt"].(time.Duration); ok && minRTT > 0 {
        log.Printf("  Min RTT: %v", minRTT)
    }
    
    if maxRTT, ok := metrics["max_rtt"].(time.Duration); ok && maxRTT > 0 {
        log.Printf("  Max RTT: %v", maxRTT)
    }
    
    if jitter, ok := metrics["jitter"].(time.Duration); ok && jitter > 0 {
        log.Printf("  Jitter: %v", jitter)
    }
    
    if packetLoss, ok := metrics["packet_loss"].(float64); ok && packetLoss > 0 {
        log.Printf("  Packet Loss: %.2f%%", packetLoss)
    }
    
    if rttSamples, ok := metrics["rtt_samples"].(int); ok && rttSamples > 0 {
        log.Printf("  RTT Samples: %d", rttSamples)
    }
    
    // Protocol-specific statistics
    if protocolStats, ok := metrics["protocol_stats"].(map[string]int64); ok && len(protocolStats) > 0 {
        log.Printf("  Protocol Distribution:")
        for protocol, count := range protocolStats {
            log.Printf("    %s: %d packets", protocol, count)
        }
    }
}

// logNetworkTopology logs network topology details including namespace and node scope.
func (ctx *EnrichedFlowContext) logNetworkTopology() {
    if ctx.NetworkTopology == nil || len(ctx.NetworkTopology) == 0 {
        return
    }
    
    log.Printf("Network Topology:")
    
    if scope, ok := ctx.NetworkTopology["scope"].(string); ok {
        log.Printf("  Namespace Scope: %s", scope)
    }
    
    if nodeScope, ok := ctx.NetworkTopology["node_scope"].(string); ok {
        log.Printf("  Node Scope: %s", nodeScope)
    }
    
    if networkMode, ok := ctx.NetworkTopology["network_mode"].(string); ok {
        log.Printf("  Network Mode: %s", networkMode)
    }
    
    if srcNamespace, ok := ctx.NetworkTopology["source_namespace"].(string); ok {
        if dstNamespace, ok := ctx.NetworkTopology["destination_namespace"].(string); ok {
            log.Printf("  Namespaces: %s -> %s", srcNamespace, dstNamespace)
        }
    }
    
    if srcNode, ok := ctx.NetworkTopology["source_node"].(string); ok {
        if dstNode, ok := ctx.NetworkTopology["destination_node"].(string); ok {
            log.Printf("  Nodes: %s -> %s", srcNode, dstNode)
        }
    }
}

// logSecurityAnalysis logs security analysis including privileged mode and capabilities.
func (ctx *EnrichedFlowContext) logSecurityAnalysis() {
    if ctx.SecurityContext == nil || len(ctx.SecurityContext) == 0 {
        return
    }
    
    log.Printf("Security Analysis:")
    
    // Security summary information
    if summary, ok := ctx.SecurityContext["security_summary"].(map[string]interface{}); ok {
        ctx.logSecuritySummary(summary)
    }
    
    // Source security context
    if srcSecurity, ok := ctx.SecurityContext["source"].(map[string]interface{}); ok {
        log.Printf("  Source Security:")
        ctx.logSecurityDetails(srcSecurity, "    ")
    }
    
    // Destination security context
    if dstSecurity, ok := ctx.SecurityContext["destination"].(map[string]interface{}); ok {
        log.Printf("  Destination Security:")
        ctx.logSecurityDetails(dstSecurity, "    ")
    }
}

// logHTTPTransactions logs completed HTTP transaction details.
func (ctx *EnrichedFlowContext) logHTTPTransactions() {
    if len(ctx.HTTPTransactions) == 0 {
        return
    }
    
    log.Printf("HTTP Transactions:")
    for _, txn := range ctx.HTTPTransactions {
        log.Printf("  Transaction: %s %s -> %d (RTT: %v)",
            txn.Method, txn.URI, txn.StatusCode, txn.RTT)
    }
}

// logSecuritySummary logs a summary of security-relevant features.
func (ctx *EnrichedFlowContext) logSecuritySummary(summary map[string]interface{}) {
    if hasPrivileged, ok := summary["has_privileged_pods"].(bool); ok && hasPrivileged {
        log.Printf("  Privileged Pods: Present")
    }
    
    if hasHostNetwork, ok := summary["has_host_network"].(bool); ok && hasHostNetwork {
        log.Printf("  Host Network Usage: Present")
    }
    
    if hasElevatedCaps, ok := summary["has_elevated_capabilities"].(bool); ok && hasElevatedCaps {
        log.Printf("  Elevated Capabilities: Present")
    }
    
    if hasDroppedCaps, ok := summary["has_dropped_capabilities"].(bool); ok && hasDroppedCaps {
        log.Printf("  Dropped Capabilities: Present")
    }
}

// logSecurityDetails logs detailed security context for a single pod.
func (ctx *EnrichedFlowContext) logSecurityDetails(security map[string]interface{}, indent string) {
    if privileged, ok := security["privileged_mode"].(bool); ok && privileged {
        log.Printf("%sPrivileged Mode: %t", indent, privileged)
    }
    
    if hostNetwork, ok := security["uses_host_network"].(bool); ok && hostNetwork {
        log.Printf("%sHost Network: %t", indent, hostNetwork)
    }
    
    if caps, ok := security["added_capabilities"].([]string); ok && len(caps) > 0 {
        log.Printf("%sAdded Capabilities: %v", indent, caps)
    }
    
    if caps, ok := security["dropped_capabilities"].([]string); ok && len(caps) > 0 {
        log.Printf("%sDropped Capabilities: %v", indent, caps)
    }
    
    if runsAsRoot, ok := security["runs_as_root"].(bool); ok && runsAsRoot {
        log.Printf("%sRuns as Root: %t", indent, runsAsRoot)
    }
    
    if allowsEscalation, ok := security["allows_privilege_escalation"].(bool); ok && allowsEscalation {
        log.Printf("%sAllows Privilege Escalation: %t", indent, allowsEscalation)
    }
}

// logSummary logs an overall summary of the enriched flow analysis.
func (ctx *EnrichedFlowContext) logSummary() {
    log.Printf("Summary:")
    log.Printf("  Flow: %s", ctx.getFlowSummary())
    log.Printf("  Security: %s", ctx.getSecuritySummary())
    log.Printf("  Performance: %s", ctx.getPerformanceSummary())
    log.Printf("  Geography: %s", ctx.getGeographySummary())
    
    if len(ctx.HTTPTransactions) > 0 {
        log.Printf("  HTTP Transactions: %d completed", len(ctx.HTTPTransactions))
    }
}

// Helper functions //

// getFlowDirection returns the flow direction based on pod presence.
func (ctx *EnrichedFlowContext) getFlowDirection() string {
    if ctx.SrcPod != nil && ctx.DstPod != nil {
        return "Pod-to-Pod"
    } else if ctx.SrcPod != nil {
        return "Pod-to-External"
    } else if ctx.DstPod != nil {
        return "External-to-Pod"
    }
    return "External-to-External"
}

// getFlowSummary returns a human-readable summary of the flow.
func (ctx *EnrichedFlowContext) getFlowSummary() string {
    direction := ctx.getFlowDirection()
    
    if ctx.SrcPod != nil && ctx.DstPod != nil {
        return fmt.Sprintf("%s (%s/%s -> %s/%s)", 
            direction, ctx.SrcPod.Namespace, ctx.SrcPod.Name, 
            ctx.DstPod.Namespace, ctx.DstPod.Name)
    }
    
    return fmt.Sprintf("%s (%s:%d -> %s:%d)", 
        direction, ctx.SrcIP, ctx.SrcPort, ctx.DstIP, ctx.DstPort)
}

// getSecuritySummary returns a brief security summary string.
func (ctx *EnrichedFlowContext) getSecuritySummary() string {
    if ctx.SecurityContext == nil {
        return "Unknown"
    }
    
    if summary, ok := ctx.SecurityContext["security_summary"].(map[string]interface{}); ok {
        var features []string
        
        if hasPrivileged, ok := summary["has_privileged_pods"].(bool); ok && hasPrivileged {
            features = append(features, "Privileged")
        }
        
        if hasHostNetwork, ok := summary["has_host_network"].(bool); ok && hasHostNetwork {
            features = append(features, "HostNetwork")
        }
        
        if hasElevatedCaps, ok := summary["has_elevated_capabilities"].(bool); ok && hasElevatedCaps {
            features = append(features, "ElevatedCaps")
        }
        
        if len(features) > 0 {
            return strings.Join(features, ", ")
        }
        
        return "Standard security"
    }
    
    return "Not analyzed"
}

// getPerformanceSummary returns a brief performance metrics summary string.
func (ctx *EnrichedFlowContext) getPerformanceSummary() string {
    if ctx.Metrics == nil {
        return "No metrics"
    }
    
    summary := ctx.Metrics.GetMetricsSummary()
    
    var parts []string
    
    if throughput, ok := summary["throughput_pps"].(float64); ok && throughput > 0 {
        parts = append(parts, FormatThroughput(throughput))
    }
    
    if bandwidth, ok := summary["bandwidth_bps"].(float64); ok && bandwidth > 0 {
        parts = append(parts, FormatBandwidth(bandwidth))
    }
    
    if avgRTT, ok := summary["avg_rtt"].(time.Duration); ok && avgRTT > 0 {
        parts = append(parts, fmt.Sprintf("RTT: %v", avgRTT))
    }
    
    if len(parts) > 0 {
        return strings.Join(parts, ", ")
    }
    
    return "Basic metrics available"
}

// getGeographySummary returns a brief geographic summary string.
func (ctx *EnrichedFlowContext) getGeographySummary() string {
    if ctx.GeoContext == nil {
        return "Unknown"
    }
    
    if ctx.GeoContext.SourceGeo != nil && ctx.GeoContext.DestinationGeo != nil {
        if ctx.GeoContext.IsInternational {
            return fmt.Sprintf("International (%s -> %s)", 
                ctx.GeoContext.SourceGeo.Country, 
                ctx.GeoContext.DestinationGeo.Country)
        } else {
            return fmt.Sprintf("Domestic (%s)", 
                ctx.GeoContext.SourceGeo.Country)
        }
    } else if ctx.GeoContext.SourceGeo != nil {
        return fmt.Sprintf("Source: %s", ctx.GeoContext.SourceGeo.Country)
    } else if ctx.GeoContext.DestinationGeo != nil {
        return fmt.Sprintf("Destination: %s", ctx.GeoContext.DestinationGeo.Country)
    }
    
    return "Partial location data"
}

// generateSecuritySummary builds a map summarizing security-relevant flags.
func (ctx *EnrichedFlowContext) generateSecuritySummary() map[string]interface{} {
    summary := make(map[string]interface{})
    
    hasPrivileged := false
    hasHostNetwork := false
    hasElevatedCaps := false
    hasDroppedCaps := false
    
    // Check source security context
    if srcSecurity, ok := ctx.SecurityContext["source"].(map[string]interface{}); ok {
        if privileged, ok := srcSecurity["privileged_mode"].(bool); ok && privileged {
            hasPrivileged = true
        }
        if hostNet, ok := srcSecurity["uses_host_network"].(bool); ok && hostNet {
            hasHostNetwork = true
        }
        if caps, ok := srcSecurity["added_capabilities"].([]string); ok && len(caps) > 0 {
            hasElevatedCaps = true
        }
        if caps, ok := srcSecurity["dropped_capabilities"].([]string); ok && len(caps) > 0 {
            hasDroppedCaps = true
        }
    }
    
    // Check destination security context
    if dstSecurity, ok := ctx.SecurityContext["destination"].(map[string]interface{}); ok {
        if privileged, ok := dstSecurity["privileged_mode"].(bool); ok && privileged {
            hasPrivileged = true
        }
        if hostNet, ok := dstSecurity["uses_host_network"].(bool); ok && hostNet {
            hasHostNetwork = true
        }
        if caps, ok := dstSecurity["added_capabilities"].([]string); ok && len(caps) > 0 {
            hasElevatedCaps = true
        }
        if caps, ok := dstSecurity["dropped_capabilities"].([]string); ok && len(caps) > 0 {
            hasDroppedCaps = true
        }
    }
    
    summary["has_privileged_pods"] = hasPrivileged
    summary["has_host_network"] = hasHostNetwork
    summary["has_elevated_capabilities"] = hasElevatedCaps
    summary["has_dropped_capabilities"] = hasDroppedCaps
    
    return summary
}

// formatBytes formats byte count into human-readable string.
func formatBytes(bytes int64) string {
    const unit = 1024
    if bytes < unit {
        return fmt.Sprintf("%d B", bytes)
    }
    div, exp := int64(unit), 0
    for n := bytes / unit; n >= unit; n /= unit {
        div *= unit
        exp++
    }
    return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// Public API functions //

// ProcessHTTPEvent processes HTTP events.
func ProcessHTTPEvent(base *protobuf.BaseNetworkEvent, isRequest bool, method, uri string, statusCode int) *EnrichedFlowContext {
    return AnalyzeEnrichedFlowWithHTTP(base, "HTTP", isRequest, method, uri, statusCode)
}

// GetHTTPTransactionStats returns HTTP transaction statistics.
func GetHTTPTransactionStats() map[string]interface{} {
    initGlobalInstances()
    
    globalHTTPTracker.mu.RLock()
    defer globalHTTPTracker.mu.RUnlock()
    
    return map[string]interface{}{
        "active_transactions": len(globalHTTPTracker.transactions),
    }
}

// ClearDeduplicationCache clears the deduplication cache.
func ClearDeduplicationCache() {
    initGlobalInstances()
    
    globalDeduplicator.mu.Lock()
    defer globalDeduplicator.mu.Unlock()
    
    globalDeduplicator.seenPackets = make(map[string]time.Time)
    log.Printf("[EnrichFlow] Deduplication cache cleared")
}

// uint32 → "x.x.x.x"
func ipToStr(ip uint32) string {
    return fmt.Sprintf("%d.%d.%d.%d",
        byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}
