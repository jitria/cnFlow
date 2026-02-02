// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package mixer

import (
    "fmt"
    "log"
    "net"
    "sync"
    "time"
    "cnFlow/protobuf"
    "cnFlow/manager/mixer/geoip"
)





type K8sMetadata struct {
    // Pod information storage (actual type: PodInfo)
    PodsByIP        map[string]*protobuf.PodInfo    // IP -> Pod mapping
    PodsByName      map[string]*protobuf.PodInfo    // namespace/name -> Pod mapping
    PodsByUID       map[string]*protobuf.PodInfo    // UID -> Pod mapping
    
    // Node information storage (actual type: NodeInfo)
    NodesByName     map[string]*protobuf.NodeInfo   // NodeName -> Node mapping
    NodesByIP       map[string]*protobuf.NodeInfo   // HostIP -> Node mapping
    
    // Service Account information
    ServiceAccounts map[string]*protobuf.ServiceAccountInfo  // namespace/name -> SA
    
    // Metadata
    LastUpdate      time.Time
    mu              sync.RWMutex
}

// FlowContext type definition (used in Handler)
type FlowContext struct {
    SrcIP   string
    DstIP   string
    SrcPod  *protobuf.PodInfo
    DstPod  *protobuf.PodInfo
    SrcNode *protobuf.NodeInfo
    DstNode *protobuf.NodeInfo
}



// NewK8sMetadata creates a new K8sMetadata store with initialized maps.
func NewK8sMetadata() *K8sMetadata {
    return &K8sMetadata{
        PodsByIP:        make(map[string]*protobuf.PodInfo),
        PodsByName:      make(map[string]*protobuf.PodInfo),
        PodsByUID:       make(map[string]*protobuf.PodInfo),
        NodesByName:     make(map[string]*protobuf.NodeInfo),
        NodesByIP:       make(map[string]*protobuf.NodeInfo),
        ServiceAccounts: make(map[string]*protobuf.ServiceAccountInfo),
        LastUpdate:      time.Now(),
    }
}



// AddPod adds a pod and its network interfaces to all metadata mappings.
func (k *K8sMetadata) AddPod(pod *protobuf.PodInfo) {
    if k == nil || pod == nil {
        log.Printf("[K8sMetadata] Warning: nil pod or metadata store")
        return
    }
    
    k.mu.Lock()
    defer k.mu.Unlock()
    
    // Basic mappings
    k.PodsByIP[pod.PodIp] = pod
    k.PodsByName[pod.Namespace+"/"+pod.Name] = pod
    k.PodsByUID[pod.PodUid] = pod
    
    // Map all network interface IPs
    if pod.NetnsInfo != nil {
        for _, iface := range pod.NetnsInfo.Interfaces {
            for _, ip := range iface.Ipv4Addresses {
                k.PodsByIP[ip] = pod
            }
            // IPv6 is a single string value
            if iface.Ipv6Addresses != "" {
                k.PodsByIP[iface.Ipv6Addresses] = pod
            }
        }
    }
    
    // Save Service Account information
    if pod.ServiceAccount != nil {
        saKey := pod.ServiceAccount.Namespace + "/" + pod.ServiceAccount.Name
        k.ServiceAccounts[saKey] = pod.ServiceAccount
    }
    
    k.LastUpdate = time.Now()
    log.Printf("[K8sMetadata] Added Pod: %s/%s (IP: %s)", 
        pod.Namespace, pod.Name, pod.PodIp)
}

// GetPodByIP retrieves a pod by its IP address.
func (k *K8sMetadata) GetPodByIP(ip string) (*protobuf.PodInfo, bool) {
    if k == nil {
        return nil, false
    }
    
    k.mu.RLock()
    defer k.mu.RUnlock()
    pod, exists := k.PodsByIP[ip]
    return pod, exists
}

// GetPodByName retrieves a pod by its namespaced name (namespace/name).
func (k *K8sMetadata) GetPodByName(namespacedName string) (*protobuf.PodInfo, bool) {
    if k == nil {
        return nil, false
    }
    
    k.mu.RLock()
    defer k.mu.RUnlock()
    pod, exists := k.PodsByName[namespacedName]
    return pod, exists
}

// GetPodByUID retrieves a pod by its UID.
func (k *K8sMetadata) GetPodByUID(uid string) (*protobuf.PodInfo, bool) {
    if k == nil {
        return nil, false
    }
    
    k.mu.RLock()
    defer k.mu.RUnlock()
    pod, exists := k.PodsByUID[uid]
    return pod, exists
}

// RemovePod removes a pod and its network interfaces from all metadata mappings.
func (k *K8sMetadata) RemovePod(pod *protobuf.PodInfo) {
    if k == nil || pod == nil {
        log.Printf("[K8sMetadata] Warning: nil pod or metadata store")
        return
    }
    
    k.mu.Lock()
    defer k.mu.Unlock()
    
    // Remove from all mappings
    delete(k.PodsByIP, pod.PodIp)
    delete(k.PodsByName, pod.Namespace+"/"+pod.Name)
    delete(k.PodsByUID, pod.PodUid)
    
    // Remove network interface IP mappings
    if pod.NetnsInfo != nil {
        for _, iface := range pod.NetnsInfo.Interfaces {
            for _, ip := range iface.Ipv4Addresses {
                delete(k.PodsByIP, ip)
            }
            if iface.Ipv6Addresses != "" {
                delete(k.PodsByIP, iface.Ipv6Addresses)
            }
        }
    }
    
    k.LastUpdate = time.Now()
    log.Printf("[K8sMetadata] Removed Pod: %s/%s (IP: %s)", 
        pod.Namespace, pod.Name, pod.PodIp)
}



// AddNode adds a node to the metadata store indexed by name and IP.
func (k *K8sMetadata) AddNode(node *protobuf.NodeInfo) {
    if k == nil || node == nil {
        log.Printf("[K8sMetadata] Warning: nil node or metadata store")
        return
    }
    
    k.mu.Lock()
    defer k.mu.Unlock()
    
    k.NodesByName[node.Name] = node
    k.NodesByIP[node.HostIp] = node
    
    k.LastUpdate = time.Now()
    log.Printf("[K8sMetadata] Added Node: %s (IP: %s)", node.Name, node.HostIp)
}

// GetNodeByName retrieves a node by its name.
func (k *K8sMetadata) GetNodeByName(name string) (*protobuf.NodeInfo, bool) {
    if k == nil {
        return nil, false
    }
    
    k.mu.RLock()
    defer k.mu.RUnlock()
    node, exists := k.NodesByName[name]
    return node, exists
}

// GetNodeByIP retrieves a node by its host IP address.
func (k *K8sMetadata) GetNodeByIP(ip string) (*protobuf.NodeInfo, bool) {
    if k == nil {
        return nil, false
    }
    
    k.mu.RLock()
    defer k.mu.RUnlock()
    node, exists := k.NodesByIP[ip]
    return node, exists
}

// RemoveNode removes a node from the metadata store by name.
func (k *K8sMetadata) RemoveNode(nodeName string) {
    if k == nil {
        log.Printf("[K8sMetadata] Warning: nil metadata store")
        return
    }
    
    k.mu.Lock()
    defer k.mu.Unlock()
    
    if node, exists := k.NodesByName[nodeName]; exists {
        delete(k.NodesByName, nodeName)
        delete(k.NodesByIP, node.HostIp)
        log.Printf("[K8sMetadata] Removed Node: %s (IP: %s)", nodeName, node.HostIp)
    }
    
    k.LastUpdate = time.Now()
}

//

//

// GetServiceAccount retrieves a service account by namespace and name.
func (k *K8sMetadata) GetServiceAccount(namespace, name string) (*protobuf.ServiceAccountInfo, bool) {
    if k == nil {
        return nil, false
    }
    
    k.mu.RLock()
    defer k.mu.RUnlock()
    
    saKey := namespace + "/" + name
    sa, exists := k.ServiceAccounts[saKey]
    return sa, exists
}

// GetServiceAccountInfo returns service account details for a pod as a map.
func (k *K8sMetadata) GetServiceAccountInfo(pod *protobuf.PodInfo) map[string]interface{} {
    if pod == nil || pod.ServiceAccount == nil {
        return nil
    }
    
    return map[string]interface{}{
        "name":                           pod.ServiceAccount.Name,
        "namespace":                      pod.ServiceAccount.Namespace,
        "automount_service_account_token": pod.ServiceAccount.AutomountServiceAccountToken,
        "secrets":                        pod.ServiceAccount.Secrets,
        "image_pull_secrets":             pod.ServiceAccount.ImagePullSecrets,
    }
}

//

//

// GetSecurityContext returns the security context for a pod as a map.
func (k *K8sMetadata) GetSecurityContext(pod *protobuf.PodInfo) map[string]interface{} {
    if pod == nil || pod.SecurityContext == nil {
        return nil
    }
    
    return map[string]interface{}{
        "run_as_non_root":            pod.SecurityContext.RunAsNonRoot,
        "run_as_user":                pod.SecurityContext.RunAsUser,
        "run_as_group":               pod.SecurityContext.RunAsGroup,
        "fs_group":                   pod.SecurityContext.FsGroup,
        "privileged":                 pod.SecurityContext.Privileged,
        "allow_privilege_escalation": pod.SecurityContext.AllowPrivilegeEscalation,
        "capabilities_add":           pod.SecurityContext.CapabilitiesAdd,
        "capabilities_drop":          pod.SecurityContext.CapabilitiesDrop,
    }
}

// AnalyzePodSecurity analyzes security properties of a pod and returns findings.
func (k *K8sMetadata) AnalyzePodSecurity(pod *protobuf.PodInfo) map[string]interface{} {
    if pod == nil {
        return nil
    }
    
    security := make(map[string]interface{})
    
    if pod.SecurityContext != nil {
        // Check privileged mode
        if pod.SecurityContext.Privileged {
            security["privileged_mode"] = true
        }
        
        // Added capabilities
        if len(pod.SecurityContext.CapabilitiesAdd) > 0 {
            security["added_capabilities"] = pod.SecurityContext.CapabilitiesAdd
            security["has_elevated_privileges"] = true
        }
        
        // Dropped capabilities
        if len(pod.SecurityContext.CapabilitiesDrop) > 0 {
            security["dropped_capabilities"] = pod.SecurityContext.CapabilitiesDrop
            security["follows_least_privilege"] = true
        }
        
        // User context
        if !pod.SecurityContext.RunAsNonRoot {
            security["runs_as_root"] = true
        }
        
        // Check if privilege escalation allowed
        if pod.SecurityContext.AllowPrivilegeEscalation {
            security["allows_privilege_escalation"] = true
        }
    }
    
    // Network security
    if pod.HostNetwork {
        security["uses_host_network"] = true
        security["network_isolation"] = false
    } else {
        security["network_isolation"] = true
    }
    
    return security
}



// AnalyzeNetworkTopology analyzes network topology between source and destination pods.
func (k *K8sMetadata) AnalyzeNetworkTopology(srcPod, dstPod *protobuf.PodInfo) map[string]interface{} {
    topology := make(map[string]interface{})
    
    if srcPod != nil && dstPod != nil {
        // Namespace analysis
        if srcPod.Namespace == dstPod.Namespace {
            topology["scope"] = "intra_namespace"
            topology["namespace"] = srcPod.Namespace
        } else {
            topology["scope"] = "cross_namespace"
            topology["source_namespace"] = srcPod.Namespace
            topology["destination_namespace"] = dstPod.Namespace
        }
        
        // Node analysis
        if srcPod.Node == dstPod.Node {
            topology["node_scope"] = "intra_node"
            topology["node"] = srcPod.Node
        } else {
            topology["node_scope"] = "inter_node"
            topology["source_node"] = srcPod.Node
            topology["destination_node"] = dstPod.Node
        }
        
        // Network mode analysis
        if srcPod.HostNetwork && dstPod.HostNetwork {
            topology["network_mode"] = "host_to_host"
        } else if srcPod.HostNetwork || dstPod.HostNetwork {
            topology["network_mode"] = "mixed_network"
        } else {
            topology["network_mode"] = "pod_to_pod"
        }
    }
    
    return topology
}



// IsClusterIP checks if an IP is internal to the cluster.
func IsClusterIP(ip string) bool {
    return !IsExternalIP(ip)
}

// GetIPType returns the type of IP as a string.
func GetIPType(ip string) string {
    if ip == "" {
        return "empty"
    }
    
    parsedIP := net.ParseIP(ip)
    if parsedIP == nil {
        return "invalid"
    }
    
    if parsedIP.IsLoopback() {
        return "loopback"
    }
    
    if parsedIP.IsPrivate() {
        return "private"
    }
    
    if parsedIP.IsLinkLocalUnicast() {
        return "link_local"
    }
    
    if parsedIP.IsMulticast() {
        return "multicast"
    }
    
    if parsedIP.IsUnspecified() {
        return "unspecified"
    }
    
    return "public"
}

// AnalyzeFlowWithGeoInfo performs comprehensive flow analysis including geographic information.
func (k *K8sMetadata) AnalyzeFlowWithGeoInfo(srcIP, dstIP string) map[string]interface{} {
    analysis := make(map[string]interface{})
    
    // Basic IP classification
    analysis["src_ip_type"] = GetIPType(srcIP)
    analysis["dst_ip_type"] = GetIPType(dstIP)
    analysis["src_is_external"] = IsExternalIP(srcIP)
    analysis["dst_is_external"] = IsExternalIP(dstIP)
    
    // Determine flow type
    srcExternal := IsExternalIP(srcIP)
    dstExternal := IsExternalIP(dstIP)
    
    if !srcExternal && !dstExternal {
        analysis["flow_type"] = "internal"
        analysis["flow_description"] = "Cluster internal communication"
    } else if srcExternal && dstExternal {
        analysis["flow_type"] = "transit"
        analysis["flow_description"] = "External-to-external transit through cluster"
    } else if srcExternal && !dstExternal {
        analysis["flow_type"] = "inbound"
        analysis["flow_description"] = "External-to-cluster inbound traffic"
    } else {
        analysis["flow_type"] = "outbound"
        analysis["flow_description"] = "Cluster-to-external outbound traffic"
    }
    
    // Look up cluster metadata
    srcPod, srcExists := k.GetPodByIP(srcIP)
    dstPod, dstExists := k.GetPodByIP(dstIP)
    
    analysis["src_has_pod"] = srcExists
    analysis["dst_has_pod"] = dstExists
    
    if srcExists {
        analysis["src_pod_namespace"] = srcPod.Namespace
        analysis["src_pod_name"] = srcPod.Name
        analysis["src_node"] = srcPod.Node
    }
    
    if dstExists {
        analysis["dst_pod_namespace"] = dstPod.Namespace
        analysis["dst_pod_name"] = dstPod.Name
        analysis["dst_node"] = dstPod.Node
    }
    
    // Geographic information analysis (for external IPs only)
    if srcExternal {
        if geoInfo := geoip.LookupIP(srcIP); geoInfo != nil {
            analysis["src_geo"] = map[string]interface{}{
                "country":  geoInfo.Country,
                "region":   geoInfo.Region,
                "city":     geoInfo.City,
                "timezone": geoInfo.Timezone,
                "isp":      geoInfo.Isp,
                "org":      geoInfo.Org,
            }
        }
    }
    
    if dstExternal {
        if geoInfo := geoip.LookupIP(dstIP); geoInfo != nil {
            analysis["dst_geo"] = map[string]interface{}{
                "country":  geoInfo.Country,
                "region":   geoInfo.Region,
                "city":     geoInfo.City,
                "timezone": geoInfo.Timezone,
                "isp":      geoInfo.Isp,
                "org":      geoInfo.Org,
            }
        }
    }
    
    // Check if international communication
    if srcGeo, srcOk := analysis["src_geo"].(map[string]interface{}); srcOk {
        if dstGeo, dstOk := analysis["dst_geo"].(map[string]interface{}); dstOk {
            srcCountry, _ := srcGeo["country"].(string)
            dstCountry, _ := dstGeo["country"].(string)
            if srcCountry != "" && dstCountry != "" {
                analysis["is_international"] = srcCountry != dstCountry
                analysis["geo_route"] = fmt.Sprintf("%s -> %s", srcCountry, dstCountry)
            }
        }
    }
    
    return analysis
}



// GetGeoInfo returns geographic information from a node.
func (k *K8sMetadata) GetGeoInfo(node *protobuf.NodeInfo) *protobuf.GeoInfo {
    if node == nil {
        return nil
    }
    return node.GeoInfo
}

// AnalyzeGeoDistribution returns geographic distribution of nodes by country, region, and city.
func (k *K8sMetadata) AnalyzeGeoDistribution() map[string]interface{} {
    if k == nil {
        return nil
    }
    
    k.mu.RLock()
    defer k.mu.RUnlock()
    
    countries := make(map[string]int)
    regions := make(map[string]int)
    cities := make(map[string]int)
    
    for _, node := range k.NodesByName {
        if node.GeoInfo != nil {
            if node.GeoInfo.Country != "" {
                countries[node.GeoInfo.Country]++
            }
            if node.GeoInfo.Region != "" {
                regions[node.GeoInfo.Region]++
            }
            if node.GeoInfo.City != "" {
                cities[node.GeoInfo.City]++
            }
        }
    }
    
    return map[string]interface{}{
        "countries": countries,
        "regions":   regions,
        "cities":    cities,
    }
}



// GetStatistics returns overall metadata store statistics.
func (k *K8sMetadata) GetStatistics() map[string]interface{} {
    if k == nil {
        return map[string]interface{}{
            "error": "metadata store not initialized",
        }
    }
    
    k.mu.RLock()
    defer k.mu.RUnlock()
    
    stats := map[string]interface{}{
        "pods_by_ip_count":    len(k.PodsByIP),
        "pods_by_name_count":  len(k.PodsByName),
        "pods_by_uid_count":   len(k.PodsByUID),
        "nodes_by_name_count": len(k.NodesByName),
        "nodes_by_ip_count":   len(k.NodesByIP),
        "service_accounts":    len(k.ServiceAccounts),
        "last_update":         k.LastUpdate,
    }
    
    // Calculate Pod count by namespace
    namespaces := make(map[string]int)
    phases := make(map[string]int)
    for _, pod := range k.PodsByName {
        namespaces[pod.Namespace]++
        phases[pod.Phase]++
    }
    stats["namespaces"] = namespaces
    stats["pod_phases"] = phases
    
    // Calculate Pod count by node
    nodeDistribution := make(map[string]int)
    for _, pod := range k.PodsByName {
        nodeDistribution[pod.Node]++
    }
    stats["node_distribution"] = nodeDistribution
    
    return stats
}

// GetPodsByNamespace returns all pods in the given namespace.
func (k *K8sMetadata) GetPodsByNamespace(namespace string) []*protobuf.PodInfo {
    if k == nil {
        return nil
    }
    
    k.mu.RLock()
    defer k.mu.RUnlock()
    
    var pods []*protobuf.PodInfo
    for _, pod := range k.PodsByName {
        if pod.Namespace == namespace {
            pods = append(pods, pod)
        }
    }
    
    return pods
}

// GetPodsByNode returns all pods scheduled on the given node.
func (k *K8sMetadata) GetPodsByNode(nodeName string) []*protobuf.PodInfo {
    if k == nil {
        return nil
    }
    
    k.mu.RLock()
    defer k.mu.RUnlock()
    
    var pods []*protobuf.PodInfo
    for _, pod := range k.PodsByName {
        if pod.Node == nodeName {
            pods = append(pods, pod)
        }
    }
    
    return pods
}

// GetPodsByPhase returns all pods in the given phase.
func (k *K8sMetadata) GetPodsByPhase(phase string) []*protobuf.PodInfo {
    if k == nil {
        return nil
    }
    
    k.mu.RLock()
    defer k.mu.RUnlock()
    
    var pods []*protobuf.PodInfo
    for _, pod := range k.PodsByName {
        if pod.Phase == phase {
            pods = append(pods, pod)
        }
    }
    
    return pods
}



// GetPodsWithElevatedPrivileges returns pods running in privileged mode or with added capabilities.
func (k *K8sMetadata) GetPodsWithElevatedPrivileges() []*protobuf.PodInfo {
    if k == nil {
        return nil
    }
    
    k.mu.RLock()
    defer k.mu.RUnlock()
    
    var privilegedPods []*protobuf.PodInfo
    for _, pod := range k.PodsByName {
        if pod.SecurityContext != nil {
            if pod.SecurityContext.Privileged || len(pod.SecurityContext.CapabilitiesAdd) > 0 {
                privilegedPods = append(privilegedPods, pod)
            }
        }
    }
    
    return privilegedPods
}

// GetPodsWithHostNetwork returns pods using the host network.
func (k *K8sMetadata) GetPodsWithHostNetwork() []*protobuf.PodInfo {
    if k == nil {
        return nil
    }
    
    k.mu.RLock()
    defer k.mu.RUnlock()
    
    var hostNetworkPods []*protobuf.PodInfo
    for _, pod := range k.PodsByName {
        if pod.HostNetwork {
            hostNetworkPods = append(hostNetworkPods, pod)
        }
    }
    
    return hostNetworkPods
}

// GetExternalFlows analyzes flow information related to external IPs.
func (k *K8sMetadata) GetExternalFlows() map[string]interface{} {
    if k == nil {
        return nil
    }
    
    k.mu.RLock()
    defer k.mu.RUnlock()
    
    stats := map[string]interface{}{
        "total_pods": len(k.PodsByName),
        "total_nodes": len(k.NodesByName),
    }
    
    // Pods using host network statistics
    hostNetworkPods := 0
    for _, pod := range k.PodsByName {
        if pod.HostNetwork {
            hostNetworkPods++
        }
    }
    stats["host_network_pods"] = hostNetworkPods
    
    // Privileged pods statistics
    privilegedPods := 0
    for _, pod := range k.PodsByName {
        if pod.SecurityContext != nil && pod.SecurityContext.Privileged {
            privilegedPods++
        }
    }
    stats["privileged_pods"] = privilegedPods
    
    return stats
}



// ValidateConsistency checks metadata store consistency and returns any issues found.
func (k *K8sMetadata) ValidateConsistency() []string {
    if k == nil {
        return []string{"metadata store not initialized"}
    }
    
    k.mu.RLock()
    defer k.mu.RUnlock()
    
    var issues []string
    
    // Pod mapping consistency check
    if len(k.PodsByIP) < len(k.PodsByName) {
        issues = append(issues, "Pod IP mapping count mismatch")
    }
    
    // Node mapping consistency check
    if len(k.NodesByName) != len(k.NodesByIP) {
        issues = append(issues, "Node mapping count mismatch")
    }
    
    // Referential integrity check
    for _, pod := range k.PodsByName {
        if _, exists := k.NodesByName[pod.Node]; !exists {
            issues = append(issues, fmt.Sprintf("Pod %s/%s references non-existent node %s", 
                pod.Namespace, pod.Name, pod.Node))
        }
    }
    
    return issues
}



// IsHealthy returns true if the metadata store has been recently updated and is consistent.
func (k *K8sMetadata) IsHealthy() bool {
    if k == nil {
        return false
    }
    
    k.mu.RLock()
    defer k.mu.RUnlock()
    
    // Basic health check: verify recent updates
    if time.Since(k.LastUpdate) > 10*time.Minute {
        return false
    }
    
    // Consistency check
    issues := k.ValidateConsistency()
    return len(issues) == 0
}

// GetHealthStatus returns the health status of the metadata store as a map.
func (k *K8sMetadata) GetHealthStatus() map[string]interface{} {
    if k == nil {
        return map[string]interface{}{
            "healthy": false,
            "error":   "metadata store not initialized",
        }
    }
    
    k.mu.RLock()
    defer k.mu.RUnlock()
    
    status := map[string]interface{}{
        "healthy":     k.IsHealthy(),
        "last_update": k.LastUpdate,
        "uptime":      time.Since(k.LastUpdate),
    }
    
    issues := k.ValidateConsistency()
    if len(issues) > 0 {
        status["issues"] = issues
    }
    
    return status
}
