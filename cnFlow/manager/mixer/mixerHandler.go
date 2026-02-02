// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package mixer

import (
    "log"
    "sync"
    "time"

    "cnFlow/protobuf"
    "cnFlow/manager/mixer/geoip"
)

type mixerHandler struct {
    waitGroup *sync.WaitGroup
    stopChan  chan struct{}

    // Kubernetes metadata store
    k8sMetadata *K8sMetadata

    // Performance metrics calculator
    metricsCalculator *MetricsCalculator

    // Global mutex
    mu sync.RWMutex
}

var MixerH *mixerHandler

// InitMixerHandler initializes the mixer handler with necessary components.
func InitMixerHandler(stopChan chan struct{}) error {
    // Initialize GeoIP
    if err := geoip.InitGeoIPResolver(); err != nil {
        log.Printf("[MixerH] GeoIP resolver init failed: %v (GeoIP feature disabled)", err)
    } else {
        log.Printf("[MixerH] GeoIP resolver initialized")
    }

    MixerH = &mixerHandler{
        stopChan:  stopChan,
        waitGroup: new(sync.WaitGroup),

        k8sMetadata: &K8sMetadata{
            PodsByIP:        make(map[string]*protobuf.PodInfo),
            PodsByName:      make(map[string]*protobuf.PodInfo),
            PodsByUID:       make(map[string]*protobuf.PodInfo),
            NodesByName:     make(map[string]*protobuf.NodeInfo),
            NodesByIP:       make(map[string]*protobuf.NodeInfo),
            ServiceAccounts: make(map[string]*protobuf.ServiceAccountInfo),
            LastUpdate:      time.Now(),
        },

        metricsCalculator: &MetricsCalculator{
            flows: make(map[string]*FlowMetrics),
        },
    }

    log.Printf("[MixerH] Mixer handler initialized")
    return nil
}

// StartMixerHandler starts the mixer handler background goroutine.
func StartMixerHandler() error {
    MixerH.waitGroup.Add(1)
    go func() {
        defer MixerH.waitGroup.Done()
        log.Printf("[MixerH] Mixer handler started")

        metricTicker := time.NewTicker(30 * time.Second)
        geoipTicker  := time.NewTicker(5 * time.Minute)
        defer metricTicker.Stop()
        defer geoipTicker.Stop()

        for {
            select {
            case <-MixerH.stopChan:
                log.Printf("[MixerH] Mixer handler stopping")
                return
            case <-metricTicker.C:
                MixerH.cleanupExpiredMetrics()
            case <-geoipTicker.C:
                MixerH.logGeoIPCacheStats()
            }
        }
    }()
    return nil
}

// WaitShutdown waits for all mixer goroutines to complete shutdown.
func WaitShutdown() {
    MixerH.waitGroup.Wait()
    geoip.CloseGeoIPResolver()
    log.Printf("[MixerH] GeoIP resolver closed")
    log.Printf("[MixerH] All mixer goroutines stopped")
}

// AddPod adds a pod to the metadata store.
func AddPod(pod *protobuf.PodInfo) {
    if MixerH == nil || MixerH.k8sMetadata == nil {
        log.Printf("[MixerH] Mixer not initialized – skip pod")
        return
    }
    MixerH.k8sMetadata.AddPod(pod)
    log.Printf("[MixerH] Added Pod: %s/%s (IP: %s)", pod.Namespace, pod.Name, pod.PodIp)
}

// GetPodByIP retrieves pod information by IP address.
func GetPodByIP(ip string) (*protobuf.PodInfo, bool) {
    if MixerH == nil || MixerH.k8sMetadata == nil {
        return nil, false
    }
    return MixerH.k8sMetadata.GetPodByIP(ip)
}

// GetPodByName retrieves pod information by namespace and name.
func GetPodByName(ns, name string) (*protobuf.PodInfo, bool) {
    if MixerH == nil || MixerH.k8sMetadata == nil {
        return nil, false
    }
    return MixerH.k8sMetadata.GetPodByName(ns + "/" + name)
}

// GetPodByUID retrieves pod information by UID.
func GetPodByUID(uid string) (*protobuf.PodInfo, bool) {
    if MixerH == nil || MixerH.k8sMetadata == nil {
        return nil, false
    }
    return MixerH.k8sMetadata.GetPodByUID(uid)
}

// AddNode adds a node to the metadata store.
func AddNode(node *protobuf.NodeInfo) {
    if MixerH == nil || MixerH.k8sMetadata == nil {
        log.Printf("[MixerH] Mixer not initialized – skip node")
        return
    }
    MixerH.k8sMetadata.AddNode(node)
    log.Printf("[MixerH] Added Node: %s (IP: %s)", node.Name, node.HostIp)
}

// GetNodeByName retrieves node information by name.
func GetNodeByName(name string) (*protobuf.NodeInfo, bool) {
    if MixerH == nil || MixerH.k8sMetadata == nil {
        return nil, false
    }
    return MixerH.k8sMetadata.GetNodeByName(name)
}

// GetNodeByIP retrieves node information by IP address.
func GetNodeByIP(ip string) (*protobuf.NodeInfo, bool) {
    if MixerH == nil || MixerH.k8sMetadata == nil {
        return nil, false
    }
    return MixerH.k8sMetadata.GetNodeByIP(ip)
}

// UpdateFlowMetrics updates metrics for the given network event.
func UpdateFlowMetrics(base *protobuf.BaseNetworkEvent) *FlowMetrics {
    if MixerH == nil || MixerH.metricsCalculator == nil {
        return nil
    }
    return MixerH.metricsCalculator.UpdateFlow(base)
}

// GetFlowMetrics retrieves flow metrics by flow key.
func GetFlowMetrics(key string) (*FlowMetrics, bool) {
    if MixerH == nil || MixerH.metricsCalculator == nil {
        return nil, false
    }
    MixerH.metricsCalculator.mu.RLock()
    defer MixerH.metricsCalculator.mu.RUnlock()
    flow, ok := MixerH.metricsCalculator.flows[key]
    return flow, ok
}

// AnalyzeFlow analyzes flow context for source and destination IPs.
func AnalyzeFlow(srcIP, dstIP string) *FlowContext {
    ctx := &FlowContext{SrcIP: srcIP, DstIP: dstIP}

    if pod, ok := GetPodByIP(srcIP); ok {
        ctx.SrcPod = pod
        if node, ok := GetNodeByName(pod.Node); ok {
            ctx.SrcNode = node
        }
    }
    if pod, ok := GetPodByIP(dstIP); ok {
        ctx.DstPod = pod
        if node, ok := GetNodeByName(pod.Node); ok {
            ctx.DstNode = node
        }
    }
    return ctx
}

// LogEnrichedFlow logs enriched flow information with protocol details.
func LogEnrichedFlow(base *protobuf.BaseNetworkEvent, protocol string) {
    if MixerH == nil {
        srcIP := ipToStr(base.SrcAddr)
        dstIP := ipToStr(base.DstAddr)
        log.Printf("Basic Flow: %s:%d -> %s:%d (%s)",
            srcIP, base.SrcPort, dstIP, base.DstPort, protocol)
        return
    }
    ctx := AnalyzeEnrichedFlow(base, protocol)
    ctx.LogCompleteAnalysis()
}

// logGeoIPCacheStats logs GeoIP cache statistics.
func (mh *mixerHandler) logGeoIPCacheStats() {
    stats := geoip.GetCacheStats()
    if stats == nil {
        return
    }
    cacheSize := stats["cache_size"].(int)
    maxSize   := stats["max_size"].(int)
    pct := float64(cacheSize) / float64(maxSize) * 100
    if pct > 80 {
        log.Printf("[MixerH] GeoIP cache usage %d/%d (%.1f%%) – high usage",
            cacheSize, maxSize, pct)
    } else if cacheSize > 0 {
        log.Printf("[MixerH] GeoIP cache usage %d/%d (%.1f%%)",
            cacheSize, maxSize, pct)
    }
}

// ClearGeoIPCache clears the GeoIP cache.
func ClearGeoIPCache() {
    geoip.ClearGeoInfoCache()
    log.Printf("[MixerH] GeoIP cache cleared")
}

// cleanupExpiredMetrics removes expired metrics from the calculator.
func (mh *mixerHandler) cleanupExpiredMetrics() {
    if mh.metricsCalculator == nil {
        return
    }
    mh.metricsCalculator.mu.Lock()
    defer mh.metricsCalculator.mu.Unlock()

    now := time.Now()
    for key, flow := range mh.metricsCalculator.flows {
        flow.mu.RLock()
        stale := now.Sub(flow.LastSeen) > 5*time.Minute
        flow.mu.RUnlock()
        if stale {
            delete(mh.metricsCalculator.flows, key)
        }
    }
}

// GetMixerStats retrieves current mixer statistics.
func GetMixerStats() map[string]interface{} {
    if MixerH == nil {
        return map[string]interface{}{"status": "not_initialized"}
    }

    MixerH.mu.RLock()
    defer MixerH.mu.RUnlock()

    stats := map[string]interface{}{
        "status": "running",
    }

    if MixerH.k8sMetadata != nil {
        MixerH.k8sMetadata.mu.RLock()
        stats["pods_count"]  = len(MixerH.k8sMetadata.PodsByIP)
        stats["nodes_count"] = len(MixerH.k8sMetadata.NodesByName)
        stats["last_update"] = MixerH.k8sMetadata.LastUpdate
        MixerH.k8sMetadata.mu.RUnlock()
    }

    if MixerH.metricsCalculator != nil {
        MixerH.metricsCalculator.mu.RLock()
        stats["active_flows"] = len(MixerH.metricsCalculator.flows)
        MixerH.metricsCalculator.mu.RUnlock()
    }

    if geo := geoip.GetCacheStats(); geo != nil {
        stats["geoip_cache"] = geo
    }
    return stats
}