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
	"cnFlow/protobuf"
)

type NamespaceMonitor struct {
	namespaces map[string]*NamespaceStats
	mu         sync.RWMutex
	ticker     *time.Ticker
	stopChan   chan struct{}
}

type NamespaceStats struct {
	Name string

	ServiceAccounts map[string]*ServiceAccountInfo

	Pods map[string]*PodInfo

	Kafka KafkaProtocolStats
	Redis RedisProtocolStats

	CrossNamespaceComms map[string]map[string]struct{}

	LastUpdated time.Time
}

type ServiceAccountInfo struct {
	Name         string
	Role         string
	Capabilities []string
}

type PodInfo struct {
	Name            string
	Geography       string
	SecurityContext string
}

type KafkaProtocolStats struct {
	Topics       map[string]struct{}
	AvgLatency   time.Duration
	Throughput   float64
	MessageCount int64
}

type RedisProtocolStats struct {
	Commands     map[string]struct{}
	AvgLatency   time.Duration
	Throughput   float64
	OperationCnt int64
}

var GlobalNamespaceMonitor *NamespaceMonitor

// InitNamespaceMonitor initializes the namespace monitor.
func InitNamespaceMonitor() {
	GlobalNamespaceMonitor = &NamespaceMonitor{
		namespaces: make(map[string]*NamespaceStats),
		ticker:     time.NewTicker(3 * time.Second),
		stopChan:   make(chan struct{}),
	}

	go GlobalNamespaceMonitor.loop()
	log.Printf("[NamespaceMonitor] Started (interval 3 s)")
}

// loop runs the periodic namespace status printing loop.
func (nm *NamespaceMonitor) loop() {
	for {
		select {
		case <-nm.ticker.C:
			nm.printStatus()
		case <-nm.stopChan:
			nm.ticker.Stop()
			return
		}
	}
}

// StopNamespaceMonitor stops the namespace monitor.
func StopNamespaceMonitor() {
	if GlobalNamespaceMonitor != nil {
		close(GlobalNamespaceMonitor.stopChan)
		log.Printf("[NamespaceMonitor] Stopped")
	}
}

// ProcessKafkaEvent processes Kafka events and updates namespace metrics.
func (nm *NamespaceMonitor) ProcessKafkaEvent(ctx *mixer.EnrichedFlowContext, ka *protocol.KafkaAnalysisResult) {
	if ctx == nil || ctx.SrcPod == nil {
		return
	}
	ns := nm.getOrCreate(ctx.SrcPod.Namespace)
	nm.updatePod(ns, ctx.SrcPod, ctx.GeoContext)
	nm.updateSA(ns, ctx.SrcPod, ctx.SecurityContext)

	if len(ctx.Metrics.RTT) > 0 {
		ns.Kafka.AvgLatency = ctx.Metrics.RTT[0]
	}
	ns.Kafka.Throughput = ctx.Metrics.Throughput
	ns.Kafka.MessageCount++

	if ka != nil && ka.Topic != "" {
		ns.Kafka.Topics[ka.Topic] = struct{}{}
	}

	if ctx.DstPod != nil && ctx.DstPod.Namespace != ns.Name {
		nm.addCrossNS(ns, ctx.DstPod.Namespace, "KAFKA")
	}

	ns.LastUpdated = time.Now()
}

// ProcessRedisEvent processes Redis events and updates namespace metrics.
func (nm *NamespaceMonitor) ProcessRedisEvent(ctx *mixer.EnrichedFlowContext, ra *protocol.RedisAnalysisResult) {
	if ctx == nil || ctx.SrcPod == nil {
		return
	}
	ns := nm.getOrCreate(ctx.SrcPod.Namespace)
	nm.updatePod(ns, ctx.SrcPod, ctx.GeoContext)
	nm.updateSA(ns, ctx.SrcPod, ctx.SecurityContext)

	if len(ctx.Metrics.RTT) > 0 {
		ns.Redis.AvgLatency = ctx.Metrics.RTT[0]
	}
	ns.Redis.Throughput = ctx.Metrics.Throughput
	ns.Redis.OperationCnt++

	if ra != nil && ra.CommandName != "" {
		ns.Redis.Commands[ra.CommandName] = struct{}{}
	}

	if ctx.DstPod != nil && ctx.DstPod.Namespace != ns.Name {
		nm.addCrossNS(ns, ctx.DstPod.Namespace, "REDIS")
	}

	ns.LastUpdated = time.Now()
}

// ProcessGeneralEvent handles general events (HTTP/DNS etc.) - updates only namespace metadata.
func (nm *NamespaceMonitor) ProcessGeneralEvent(ctx *mixer.EnrichedFlowContext) {
	if ctx == nil || ctx.SrcPod == nil {
		return
	}
	ns := nm.getOrCreate(ctx.SrcPod.Namespace)
	nm.updatePod(ns, ctx.SrcPod, ctx.GeoContext)
	nm.updateSA(ns, ctx.SrcPod, ctx.SecurityContext)

	if ctx.DstPod != nil && ctx.DstPod.Namespace != ns.Name {
		nm.addCrossNS(ns, ctx.DstPod.Namespace, ctx.Protocol)
	}

	ns.LastUpdated = time.Now()
}

/////////////////////////
//  Update Sub-Helpers //
/////////////////////////

// getOrCreate returns existing namespace stats or creates a new entry.
func (nm *NamespaceMonitor) getOrCreate(nsName string) *NamespaceStats {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	ns, ok := nm.namespaces[nsName]
	if !ok {
		ns = &NamespaceStats{
			Name:                nsName,
			ServiceAccounts:     map[string]*ServiceAccountInfo{},
			Pods:                map[string]*PodInfo{},
			Kafka:               KafkaProtocolStats{Topics: map[string]struct{}{}},
			Redis:               RedisProtocolStats{Commands: map[string]struct{}{}},
			CrossNamespaceComms: map[string]map[string]struct{}{},
		}
		nm.namespaces[nsName] = ns
	}
	return ns
}

// updatePod updates pod tracking information within a namespace.
func (nm *NamespaceMonitor) updatePod(ns *NamespaceStats, pod *protobuf.PodInfo, geo *mixer.GeoContext) {
	var geoStr string
	if geo != nil && geo.SourceGeo != nil {
		geoStr = fmt.Sprintf("%s, %s", geo.SourceGeo.Region, geo.SourceGeo.Country)
	}
	netMode := "podNetwork"
	if pod.HostNetwork {
		netMode = "hostNetwork:true"
	}
	ns.Pods[pod.Name] = &PodInfo{
		Name:            pod.Name,
		Geography:       geoStr,
		SecurityContext: netMode,
	}
}

// updateSA updates service account information for a pod within a namespace.
func (nm *NamespaceMonitor) updateSA(ns *NamespaceStats, pod *protobuf.PodInfo, secCtx map[string]interface{}) {
	if pod.ServiceAccount == nil {
		return
	}
	role := "application"
	switch {
	case strings.Contains(pod.Name, "kafka"):
		role = "kafka-operator"
	case strings.Contains(pod.Name, "redis"):
		role = "cache-manager"
	case strings.Contains(pod.Name, "flannel"):
		role = "network-operator"
	}

	var caps []string
	if secCtx != nil {
		if src, ok := secCtx["source"].(map[string]interface{}); ok {
			if add, ok := src["added_capabilities"].([]interface{}); ok {
				for _, c := range add {
					if cs, ok := c.(string); ok {
						caps = append(caps, cs)
					}
				}
			}
		}
	}

	ns.ServiceAccounts[pod.ServiceAccount.Name] = &ServiceAccountInfo{
		Name:         pod.ServiceAccount.Name,
		Role:         role,
		Capabilities: caps,
	}
}

// addCrossNS records a cross-namespace communication between namespaces.
func (nm *NamespaceMonitor) addCrossNS(ns *NamespaceStats, target, proto string) {
	if ns.CrossNamespaceComms[target] == nil {
		ns.CrossNamespaceComms[target] = map[string]struct{}{}
	}
	ns.CrossNamespaceComms[target][proto] = struct{}{}
}

/////////////////////////
//  Periodic Printing  //
/////////////////////////

// printStatus prints the current status of all namespaces.
func (nm *NamespaceMonitor) printStatus() {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	log.Println("==================== NAMESPACE STATUS ====================")
	log.Printf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))

	if len(nm.namespaces) == 0 {
		log.Println("No namespace activity detected yet…")
		log.Println("==========================================================")
		return
	}

	var names []string
	for n := range nm.namespaces {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		nm.printSingleNamespace(nm.namespaces[n])
		log.Println()
	}
	log.Println("==========================================================")
}

// printSingleNamespace prints the status of a single namespace.
func (nm *NamespaceMonitor) printSingleNamespace(ns *NamespaceStats) {
	log.Printf("Namespace: %s", ns.Name)

	// ServiceAccounts
	log.Println("ServiceAccounts:")
	if len(ns.ServiceAccounts) == 0 {
		log.Println("  └── (none)")
	} else {
		keys := sortedKeysSA(ns.ServiceAccounts)
		for i, k := range keys {
			prefix := branchPrefix(i, len(keys))
			sa := ns.ServiceAccounts[k]
			capStr := "none"
			if len(sa.Capabilities) > 0 {
				capStr = strings.Join(sa.Capabilities, ", ")
			}
			log.Printf("%s %s (Role: %s, Capabilities: %s)", prefix, sa.Name, sa.Role, capStr)
		}
	}

	// Pods
	log.Println("Pods Composition:")
	if len(ns.Pods) == 0 {
		log.Println("  └── (none)")
	} else {
		keys := sortedKeysPod(ns.Pods)
		for i, k := range keys {
			prefix := branchPrefix(i, len(keys))
			p := ns.Pods[k]
			log.Printf("%s %s (%s, %s)", prefix, p.Name, p.Geography, p.SecurityContext)
		}
	}

	// Protocol Distribution
	log.Println("Protocol Distribution:")
	added := false

	if ns.Kafka.MessageCount > 0 {
		added = true
		prefix := "  ├──"
		lat := ms(ns.Kafka.AvgLatency)
		tp := fmt.Sprintf("%.1fK msg/s", ns.Kafka.Throughput/1000)

		var topics []string
		for topic := range ns.Kafka.Topics {
			topics = append(topics, topic)
		}
		sort.Strings(topics)
		topicsStr := strings.Join(topics, ", ")
		if len(topicsStr) > 50 {
			topicsStr = topicsStr[:47] + "..."
		}

		log.Printf("%s KAFKA: %d topics (%s), %s avg, %s",
			prefix, len(ns.Kafka.Topics), topicsStr, lat, tp)
	}

	if ns.Redis.OperationCnt > 0 {
		prefix := "  └──"
		if !added {
			prefix = "  ├──"
		}
		lat := ms(ns.Redis.AvgLatency)
		tp := fmt.Sprintf("%.1fK ops/s", ns.Redis.Throughput/1000)

		var commands []string
		for cmd := range ns.Redis.Commands {
			commands = append(commands, cmd)
		}
		sort.Strings(commands)
		commandsStr := strings.Join(commands, ", ")
		if len(commandsStr) > 40 {
			commandsStr = commandsStr[:37] + "..."
		}

		log.Printf("%s REDIS: %d commands (%s), %s avg, %s",
			prefix, len(ns.Redis.Commands), commandsStr, lat, tp)
	}

	if !added && ns.Redis.OperationCnt == 0 {
		log.Println("  └── (no protocol activity)")
	}

	// Cross-Namespace
	log.Println("Cross-Namespace Communications:")
	if len(ns.CrossNamespaceComms) == 0 {
		log.Println("  └── (none)")
	} else {
		targets := sortedKeysCross(ns.CrossNamespaceComms)
		for i, t := range targets {
			prefix := branchPrefix(i, len(targets))
			var protos []string
			for p := range ns.CrossNamespaceComms[t] {
				protos = append(protos, p)
			}
			sort.Strings(protos)
			log.Printf("%s %s (%s)", prefix, t, strings.Join(protos, ", "))
		}
	}
}

/////////////////////////
//        Utils        //
/////////////////////////

// branchPrefix returns a tree-style branch prefix for list printing.
func branchPrefix(i, total int) string {
	if i == total-1 {
		return "  └──"
	}
	return "  ├──"
}

// sortedKeysSA returns sorted keys from a ServiceAccountInfo map.
func sortedKeysSA(m map[string]*ServiceAccountInfo) []string {
	var s []string
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}

// sortedKeysPod returns sorted keys from a PodInfo map.
func sortedKeysPod(m map[string]*PodInfo) []string {
	var s []string
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}

// sortedKeysCross returns sorted keys from a cross-namespace communications map.
func sortedKeysCross(m map[string]map[string]struct{}) []string {
	var s []string
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}

// ms formats a duration as a millisecond string.
func ms(d time.Duration) string {
	if d == 0 {
		return "0.0ms"
	}
	return fmt.Sprintf("%.1fms", float64(d.Nanoseconds())/1e6)
}
