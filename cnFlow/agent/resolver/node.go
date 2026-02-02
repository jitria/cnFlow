// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package resolver

import (
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "strconv"
    "strings"
    "time"

    v1 "k8s.io/api/core/v1"
    "cnFlow/types"
    "cnFlow/agent/attacher"
    "cnFlow/agent/uploader"
)

// ProcessNodeEvent dispatches node add/delete events to the appropriate handler.
func ProcessNodeEvent(eventType string, node *v1.Node) {
    switch eventType {
    case "ADD":
        handleNodeAdd(node)
    case "DELETE":
        handleNodeDelete(node)
    default:
        log.Printf("[Resolver] Unknown node event type: %s", eventType)
    }
}

// ProcessNodeUpdateEvent handles node update events.
func ProcessNodeUpdateEvent(oldNode, newNode *v1.Node) {
    handleNodeUpdate(oldNode, newNode)
}

// handleNodeAdd registers the node and sets up eBPF monitoring for it.
func handleNodeAdd(node *v1.Node) {
    log.Printf("[Resolver] Processing node add: %s", node.Name)

    nodeInfo := convertNodeToNodeInfo(node)

    uploader.RegisterNodeToMap(nodeInfo.HostIP, nodeInfo)

    setupEBPFForNode(nodeInfo)
}

// handleNodeUpdate re-registers the node and updates eBPF if needed.
func handleNodeUpdate(oldNode, newNode *v1.Node) {
    log.Printf("[Resolver] Processing node update: %s", newNode.Name)

    oldNodeInfo := convertNodeToNodeInfo(oldNode)
    newNodeInfo := convertNodeToNodeInfo(newNode)

    uploader.UnregisterNodeFromMap(oldNodeInfo.HostIP)

    uploader.RegisterNodeToMap(newNodeInfo.HostIP, newNodeInfo)

    if shouldUpdateNodeEBPF(oldNodeInfo, newNodeInfo) {
        cleanupEBPFForNode(oldNodeInfo)
        setupEBPFForNode(newNodeInfo)
    }
}

// handleNodeDelete unregisters the node and cleans up eBPF resources.
func handleNodeDelete(node *v1.Node) {
    log.Printf("[Resolver] Processing node delete: %s", node.Name)

    nodeInfo := convertNodeToNodeInfo(node)

    uploader.UnregisterNodeFromMap(nodeInfo.HostIP)

    cleanupEBPFForNode(nodeInfo)
}

// convertNodeToNodeInfo converts a Kubernetes Node object to the internal NodeInfo type.
func convertNodeToNodeInfo(node *v1.Node) types.NodeInfo {
    netnsInfo := collectHostNamespaceInfo()

    return types.NodeInfo{
        Name:           node.Name,
        UID:            string(node.UID),
        Status:         string(node.Status.Phase),
        HostIP:         getNodeHostIP(node),
        KubeletVersion: node.Status.NodeInfo.KubeletVersion,
        OSImage:        node.Status.NodeInfo.OSImage,
        Allocatable:    node.Status.Allocatable,
        Capacity:       node.Status.Capacity,
        NetNsInfo:      *netnsInfo,

        GeoInfo:        getGeoInfo(),
    }
}

// getNodeHostIP returns the internal IP address of the node.
func getNodeHostIP(node *v1.Node) string {
    for _, addr := range node.Status.Addresses {
        if addr.Type == v1.NodeInternalIP {
            return addr.Address
        }
    }
    if len(node.Status.Addresses) > 0 {
        return node.Status.Addresses[0].Address
    }
    return ""
}

// getGeoInfo fetches geographic location data from the ip-api.com service.
func getGeoInfo() types.GeoInfo {
    geoInfo := types.GeoInfo{}

    client := &http.Client{
        Timeout: 10 * time.Second,
    }

    resp, err := client.Get("http://ip-api.com/json/")
    if err != nil {
        log.Printf("[Resolver] Failed to get geo info: %v", err)
        return geoInfo
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        log.Printf("[Resolver] Failed to read response body: %v", err)
        return geoInfo
    }

    var apiResp struct {
        Status      string  `json:"status"`
        Country     string  `json:"country"`
        RegionName  string  `json:"regionName"`
        City        string  `json:"city"`
        Timezone    string  `json:"timezone"`
        Lat         float64 `json:"lat"`
        Lon         float64 `json:"lon"`
        ISP         string  `json:"isp"`
        Org         string  `json:"org"`
        AS          string  `json:"as"`
    }

    if err := json.Unmarshal(body, &apiResp); err != nil {
        log.Printf("[Resolver] Failed to decode geo info response: %v", err)
        return geoInfo
    }

    if apiResp.Status != "success" {
        log.Printf("[Resolver] API returned status: %s", apiResp.Status)
        return geoInfo
    }

    asNumber := int32(0)
    asName := ""
    if apiResp.AS != "" {
        parts := strings.SplitN(apiResp.AS, " ", 2)
        if len(parts) >= 1 && strings.HasPrefix(parts[0], "AS") {
            if num, err := strconv.Atoi(parts[0][2:]); err == nil {
                asNumber = int32(num)
            }
        }
        if len(parts) >= 2 {
            asName = parts[1]
        }
    }

    geoInfo = types.GeoInfo{
        Country:   apiResp.Country,
        Region:    apiResp.RegionName,
        City:      apiResp.City,
        Timezone:  apiResp.Timezone,
        Latitude:  apiResp.Lat,
        Longitude: apiResp.Lon,
        ISP:       apiResp.ISP,
        Org:       apiResp.Org,
        ASName:    asName,
        ASNumber:  asNumber,
    }

    log.Printf("[Resolver] Full Node's geo info: %+v", geoInfo)

    return geoInfo
}

// setupEBPFForNode attaches TC eBPF programs to all interfaces of the node.
func setupEBPFForNode(nodeInfo types.NodeInfo) {
    log.Printf("[Resolver] Setting up eBPF for node: %s", nodeInfo.Name)

    for _, iface := range nodeInfo.NetNsInfo.Interfaces {
        ctx, err := attacher.SetupTC(nodeInfo.NetNsInfo.Name, iface, nodeInfo.Name)
        if err != nil {
            log.Printf("[Resolver] Failed to setup eBPF for node %s interface %s: %v",
                nodeInfo.Name, iface.Name, err)
            continue
        }

        startNodeEBPFMonitoring(nodeInfo, iface, ctx)
    }
}

// startNodeEBPFMonitoring launches a goroutine to monitor eBPF events for a node interface.
func startNodeEBPFMonitoring(nodeInfo types.NodeInfo, iface types.NetworkInterfaceInfo, ctx *attacher.BPFContext) {
    stopChan := make(chan struct{})
    key := fmt.Sprintf("%s|%s", nodeInfo.Name, iface.Name)
    addNodeStopChan(key, stopChan)

    ResolverH.waitGroup.Add(1)
    go func() {
        defer ResolverH.waitGroup.Done()
        defer func() {
            attacher.CleanupEBPF(ctx)
            removeNodeStopChan(key)
        }()

        attacher.StartEBPFMonitoring(stopChan, ctx)

        <-stopChan
        log.Printf("[Resolver] Stopped eBPF monitoring for node %s interface %s", nodeInfo.Name, iface.Name)
    }()
}

// cleanupEBPFForNode closes all eBPF stop channels associated with the node.
func cleanupEBPFForNode(nodeInfo types.NodeInfo) {
    log.Printf("[Resolver] Cleaning up eBPF for node: %s", nodeInfo.Name)

    prefix := nodeInfo.Name + "|"
    ResolverH.mu.Lock()
    var keysToDelete []string
    for key := range ResolverH.nodeStopChans {
        if strings.HasPrefix(key, prefix) {
            keysToDelete = append(keysToDelete, key)
        }
    }
    ResolverH.mu.Unlock()

    for _, key := range keysToDelete {
        removeNodeStopChan(key)
    }
}

// shouldUpdateNodeEBPF returns true if the node change requires eBPF reattachment.
func shouldUpdateNodeEBPF(oldNodeInfo, newNodeInfo types.NodeInfo) bool {
    return oldNodeInfo.HostIP != newNodeInfo.HostIP ||
           oldNodeInfo.Status != newNodeInfo.Status
}

// addNodeStopChan registers a stop channel for a node interface monitoring goroutine.
func addNodeStopChan(key string, stopChan chan struct{}) {
    ResolverH.mu.Lock()
    defer ResolverH.mu.Unlock()
    ResolverH.nodeStopChans[key] = stopChan
}

// removeNodeStopChan closes and removes the stop channel for a node interface.
func removeNodeStopChan(key string) {
    ResolverH.mu.Lock()
    defer ResolverH.mu.Unlock()
    if stopChan, exists := ResolverH.nodeStopChans[key]; exists {
        close(stopChan)
        delete(ResolverH.nodeStopChans, key)
    }
}
