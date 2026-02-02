// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package parser

import (
    "fmt"
    "strings"
    "time"

    "cnFlow/protobuf"
    "cnFlow/manager/parser/protocol"
    "cnFlow/manager/mixer"
)

// formatLatencyFromDuration converts time.Duration to milliseconds.
func formatLatencyFromDuration(rtt []time.Duration) string {
    if len(rtt) == 0 {
        return ""
    }
    
    latencyMs := float64(rtt[0].Nanoseconds()) / 1000000
    return fmt.Sprintf("%.2fms", latencyMs)
}

// formatBytes formats byte size as a string.
func formatBytes(size uint32) string {
    if size == 0 {
        return "0B"
    }
    return fmt.Sprintf("%dB", size)
}

// formatTCPFlagsFromStruct formats TCP flags from a string slice.
func formatTCPFlagsFromStruct(flagNames []string) string {
    if len(flagNames) == 0 {
        return ""
    }
    return strings.Join(flagNames, "+")
}

// extractCapabilitiesFromMap extracts capabilities information from SecurityContext map.
func extractCapabilitiesFromMap(securityContext map[string]interface{}) string {
    if securityContext == nil {
        return ""
    }
    
    source, ok := securityContext["source"].(map[string]interface{})
    if !ok {
        return ""
    }
    
    capabilities, ok := source["added_capabilities"].([]interface{})
    if !ok || len(capabilities) == 0 {
        return ""
    }
    
    var caps []string
    for _, cap := range capabilities {
        if capStr, ok := cap.(string); ok {
            caps = append(caps, capStr)
        }
    }
    
    return strings.Join(caps, "+")
}

// extractUIDFromMap extracts UID information from SecurityContext map.
func extractUIDFromMap(securityContext map[string]interface{}) string {
    if securityContext == nil {
        return ""
    }
    
    source, ok := securityContext["source"].(map[string]interface{})
    if !ok {
        return ""
    }
    
    runsAsRoot, ok := source["runs_as_root"].(bool)
    if ok && runsAsRoot {
        return "uid:root"
    }
    
    if runAsUser, exists := source["run_as_user"]; exists {
        if uid, ok := runAsUser.(float64); ok {
            return fmt.Sprintf("uid:%d", int(uid))
        }
        if uid, ok := runAsUser.(int); ok {
            return fmt.Sprintf("uid:%d", uid)
        }
    }
    
    return ""
}

// formatPodInfoFromProtobuf formats Pod information from protobuf.PodInfo.
func formatPodInfoFromProtobuf(pod *protobuf.PodInfo, geoContext *mixer.GeoContext, ip string, port uint32, isSource bool) string {
    if pod == nil {
        return fmt.Sprintf("external(%s:%d)", ip, port)
    }

    var geoInfo []string
    var geo *protobuf.GeoInfo
    if isSource {
        geo = geoContext.SourceGeo
    } else {
        geo = geoContext.DestinationGeo
    }
    
    if geo != nil {
        if geo.Region != "" {
            geoInfo = append(geoInfo, geo.Region)
        }
        if geo.Country != "" {
            geoInfo = append(geoInfo, geo.Country)
        }
    }

    networkMode := "pod-network"
    if pod.HostNetwork {
        networkMode = "host-network"
    }

    var saInfo string
    if pod.ServiceAccount != nil && pod.ServiceAccount.Name != "" {
        saInfo = fmt.Sprintf("sa:%s", pod.ServiceAccount.Name)
    }

    var infoComponents []string
    if len(geoInfo) > 0 {
        infoComponents = append(infoComponents, strings.Join(geoInfo, ", "))
    }
    infoComponents = append(infoComponents, fmt.Sprintf("%s:%d", ip, port))
    if networkMode != "" {
        infoComponents = append(infoComponents, networkMode)
    }
    if saInfo != "" {
        infoComponents = append(infoComponents, saInfo)
    }

    return fmt.Sprintf("%s/%s(%s)", pod.Namespace, pod.Name, strings.Join(infoComponents, ", "))
}

// formatDNSServerInfoFromGeoContext formats DNS server information using GeoContext.
func formatDNSServerInfoFromGeoContext(dstIP string, dstPort uint32, geoContext *mixer.GeoContext) string {
    if dstIP == "127.0.0.53" {
        return fmt.Sprintf("systemd-resolved(localhost, local-resolver, %s:%d)", dstIP, dstPort)
    }

    var geoInfo []string
    if geoContext.DestinationGeo != nil {
        if geoContext.DestinationGeo.Region != "" {
            geoInfo = append(geoInfo, geoContext.DestinationGeo.Region)
        }
        if geoContext.DestinationGeo.Country != "" {
            geoInfo = append(geoInfo, geoContext.DestinationGeo.Country)
        }
    }

    var infoComponents []string
    if len(geoInfo) > 0 {
        infoComponents = append(infoComponents, strings.Join(geoInfo, ", "))
    }
    infoComponents = append(infoComponents, fmt.Sprintf("%s:%d", dstIP, dstPort))
    infoComponents = append(infoComponents, "external-dns")

    return fmt.Sprintf("dns-server(%s)", strings.Join(infoComponents, ", "))
}

// FormatHTTPEvent formats HTTP events in the specified format.
func FormatHTTPEvent(enrichedCtx *mixer.EnrichedFlowContext, httpAnalysis *protocol.HTTPAnalysisResult) string {
    srcIP := enrichedCtx.SrcIP
    dstIP := enrichedCtx.DstIP
    srcPort := enrichedCtx.SrcPort
    dstPort := enrichedCtx.DstPort

    method := httpAnalysis.Method
    uri := httpAnalysis.URI
    statusCode := httpAnalysis.StatusCode
    payloadSize := httpAnalysis.BaseInfo.PayloadSize

    tcpFlags := formatTCPFlagsFromStruct(httpAnalysis.BaseInfo.TCPHeader.FlagNames)
    sequenceNum := httpAnalysis.BaseInfo.TCPHeader.SeqNumber

    ttl := httpAnalysis.BaseInfo.IPHeader.TTL

    var responseCategory string
    if statusCode != "" {
        switch {
        case strings.HasPrefix(statusCode, "2"):
            responseCategory = "2xx-Success"
        case strings.HasPrefix(statusCode, "4"):
            responseCategory = "4xx-ClientError"
        case strings.HasPrefix(statusCode, "5"):
            responseCategory = "5xx-ServerError"
        default:
            responseCategory = statusCode
        }
    } else {
        responseCategory = "Request"
    }

    srcPodInfo := formatPodInfoFromProtobuf(enrichedCtx.SrcPod, enrichedCtx.GeoContext, srcIP, srcPort, true)

    var dstPodInfo string
    if enrichedCtx.DstPod != nil {
        dstPodInfo = formatPodInfoFromProtobuf(enrichedCtx.DstPod, enrichedCtx.GeoContext, dstIP, dstPort, false)
    } else {
        dstPodInfo = fmt.Sprintf("external-service(%s:%d)", dstIP, dstPort)
    }

    var latency string
    if len(enrichedCtx.Metrics.RTT) > 0 {
        latency = formatLatencyFromDuration(enrichedCtx.Metrics.RTT)
    }
    
    // Security context (map[string]interface{} type)
    uid := extractUIDFromMap(enrichedCtx.SecurityContext)
    capabilities := extractCapabilitiesFromMap(enrichedCtx.SecurityContext)

    // Construct HTTP header information (exclude empty values)
    var httpFields []string
    if statusCode != "" {
        httpFields = append(httpFields, statusCode)
    }
    if method != "" {
        httpFields = append(httpFields, method)
    }
    if uri != "" {
        httpFields = append(httpFields, uri)
    }
    httpFields = append(httpFields, formatBytes(payloadSize))
    httpFields = append(httpFields, responseCategory)
    if tcpFlags != "" {
        httpFields = append(httpFields, tcpFlags)
    }

    // Construct protocol information (exclude empty values)
    var protocolInfo []string
    if latency != "" {
        protocolInfo = append(protocolInfo, latency)
    }
    if uid != "" {
        protocolInfo = append(protocolInfo, uid)
    }
    if capabilities != "" {
        protocolInfo = append(protocolInfo, capabilities)
    }
    protocolInfo = append(protocolInfo, fmt.Sprintf("ttl:%d", ttl))
    protocolInfo = append(protocolInfo, fmt.Sprintf("seq:%d", sequenceNum))

    // Final formatting
    return fmt.Sprintf(`[%s]
%s
=== HTTP/1.1(%s) ===>
%s`,
        strings.Join(httpFields, ", "),
        srcPodInfo,
        strings.Join(protocolInfo, ", "),
        dstPodInfo)
}

// FormatHTTP2Event formats HTTP2 events in the specified format.
func FormatHTTP2Event(enrichedCtx *mixer.EnrichedFlowContext, http2Analysis *protocol.HTTP2AnalysisResult) string {
    srcIP := enrichedCtx.SrcIP
    dstIP := enrichedCtx.DstIP
    srcPort := enrichedCtx.SrcPort
    dstPort := enrichedCtx.DstPort

    frameType := http2Analysis.FrameTypeName
    streamID := http2Analysis.StreamID
    frameLength := http2Analysis.FrameLength
    payloadSize := http2Analysis.BaseInfo.PayloadSize

    tcpFlags := formatTCPFlagsFromStruct(http2Analysis.BaseInfo.TCPHeader.FlagNames)
    sequenceNum := http2Analysis.BaseInfo.TCPHeader.SeqNumber
    ttl := http2Analysis.BaseInfo.IPHeader.TTL

    // Extract method/status if HEADERS frame
    var method, path, status string
    if http2Analysis.HeadersAnalysis != nil {
        method = http2Analysis.HeadersAnalysis.Method
        path = http2Analysis.HeadersAnalysis.Path
        status = http2Analysis.HeadersAnalysis.Status
    }

    // Frame flags
    var flags []string
    if http2Analysis.FrameAnalysis != nil {
        flags = http2Analysis.FrameAnalysis.Flags
    }

    srcPodInfo := formatPodInfoFromProtobuf(enrichedCtx.SrcPod, enrichedCtx.GeoContext, srcIP, srcPort, true)
    var dstPodInfo string
    if enrichedCtx.DstPod != nil {
        dstPodInfo = formatPodInfoFromProtobuf(enrichedCtx.DstPod, enrichedCtx.GeoContext, dstIP, dstPort, false)
    } else {
        dstPodInfo = fmt.Sprintf("external-service(%s:%d)", dstIP, dstPort)
    }

    var latency string
    if len(enrichedCtx.Metrics.RTT) > 0 {
        latency = formatLatencyFromDuration(enrichedCtx.Metrics.RTT)
    }
    uid := extractUIDFromMap(enrichedCtx.SecurityContext)
    capabilities := extractCapabilitiesFromMap(enrichedCtx.SecurityContext)

    // HTTP2 header fields
    var h2Fields []string
    h2Fields = append(h2Fields, frameType)
    h2Fields = append(h2Fields, fmt.Sprintf("stream:%d", streamID))
    if method != "" {
        h2Fields = append(h2Fields, method)
    }
    if path != "" {
        h2Fields = append(h2Fields, path)
    }
    if status != "" {
        h2Fields = append(h2Fields, fmt.Sprintf("status:%s", status))
    }
    h2Fields = append(h2Fields, fmt.Sprintf("frame:%dB", frameLength))
    h2Fields = append(h2Fields, formatBytes(payloadSize))
    if len(flags) > 0 {
        h2Fields = append(h2Fields, strings.Join(flags, "+"))
    }
    if tcpFlags != "" {
        h2Fields = append(h2Fields, tcpFlags)
    }

    var protocolInfo []string
    if latency != "" {
        protocolInfo = append(protocolInfo, latency)
    }
    if uid != "" {
        protocolInfo = append(protocolInfo, uid)
    }
    if capabilities != "" {
        protocolInfo = append(protocolInfo, capabilities)
    }
    protocolInfo = append(protocolInfo, fmt.Sprintf("ttl:%d", ttl))
    protocolInfo = append(protocolInfo, fmt.Sprintf("seq:%d", sequenceNum))

    return fmt.Sprintf(`[%s]
%s
=== HTTP/2(%s) ===>
%s`,
        strings.Join(h2Fields, ", "),
        srcPodInfo,
        strings.Join(protocolInfo, ", "),
        dstPodInfo)
}

// FormatRedisEvent formats Redis events in the specified format.
func FormatRedisEvent(enrichedCtx *mixer.EnrichedFlowContext, redisAnalysis *protocol.RedisAnalysisResult) string {
    srcIP := enrichedCtx.SrcIP
    dstIP := enrichedCtx.DstIP
    srcPort := enrichedCtx.SrcPort
    dstPort := enrichedCtx.DstPort

    commandName := redisAnalysis.CommandName
    respTypeName := redisAnalysis.RespTypeName
    payloadSize := redisAnalysis.BaseInfo.PayloadSize

    tcpFlags := formatTCPFlagsFromStruct(redisAnalysis.BaseInfo.TCPHeader.FlagNames)
    sequenceNum := redisAnalysis.BaseInfo.TCPHeader.SeqNumber
    ttl := redisAnalysis.BaseInfo.IPHeader.TTL

    // Key information
    var keyInfo string
    if redisAnalysis.KeyValueInfo != nil && redisAnalysis.KeyValueInfo.Key != "" {
        keyInfo = redisAnalysis.KeyValueInfo.Key
    }

    // Command purpose
    var purpose string
    if redisAnalysis.CommandAnalysis != nil {
        purpose = redisAnalysis.CommandAnalysis.Operation
    }
    if redisAnalysis.ResponseAnalysis != nil {
        purpose = redisAnalysis.ResponseAnalysis.Type
    }

    srcPodInfo := formatPodInfoFromProtobuf(enrichedCtx.SrcPod, enrichedCtx.GeoContext, srcIP, srcPort, true)
    var dstPodInfo string
    if enrichedCtx.DstPod != nil {
        dstPodInfo = formatPodInfoFromProtobuf(enrichedCtx.DstPod, enrichedCtx.GeoContext, dstIP, dstPort, false)
    } else {
        dstPodInfo = fmt.Sprintf("external-service(%s:%d)", dstIP, dstPort)
    }

    var latency string
    if len(enrichedCtx.Metrics.RTT) > 0 {
        latency = formatLatencyFromDuration(enrichedCtx.Metrics.RTT)
    }
    uid := extractUIDFromMap(enrichedCtx.SecurityContext)
    capabilities := extractCapabilitiesFromMap(enrichedCtx.SecurityContext)

    var direction string
    if redisAnalysis.IsRequest {
        direction = "Request"
    } else {
        direction = "Response"
    }

    var redisFields []string
    redisFields = append(redisFields, direction)
    redisFields = append(redisFields, commandName)
    if keyInfo != "" {
        redisFields = append(redisFields, fmt.Sprintf("key:%s", keyInfo))
    }
    redisFields = append(redisFields, respTypeName)
    redisFields = append(redisFields, formatBytes(payloadSize))
    if purpose != "" {
        redisFields = append(redisFields, purpose)
    }
    if tcpFlags != "" {
        redisFields = append(redisFields, tcpFlags)
    }

    var protocolInfo []string
    if latency != "" {
        protocolInfo = append(protocolInfo, latency)
    }
    if uid != "" {
        protocolInfo = append(protocolInfo, uid)
    }
    if capabilities != "" {
        protocolInfo = append(protocolInfo, capabilities)
    }
    protocolInfo = append(protocolInfo, fmt.Sprintf("ttl:%d", ttl))
    protocolInfo = append(protocolInfo, fmt.Sprintf("seq:%d", sequenceNum))

    return fmt.Sprintf(`[%s]
%s
=== REDIS/TCP(%s) ===>
%s`,
        strings.Join(redisFields, ", "),
        srcPodInfo,
        strings.Join(protocolInfo, ", "),
        dstPodInfo)
}

// FormatKafkaEvent formats Kafka events in the specified format.
func FormatKafkaEvent(enrichedCtx *mixer.EnrichedFlowContext, kafkaAnalysis *protocol.KafkaAnalysisResult) string {
    srcIP := enrichedCtx.SrcIP
    dstIP := enrichedCtx.DstIP
    srcPort := enrichedCtx.SrcPort
    dstPort := enrichedCtx.DstPort

    apiKeyName := kafkaAnalysis.ApiKeyName
    apiVersion := kafkaAnalysis.ApiVersion
    correlationID := kafkaAnalysis.CorrelationID
    payloadSize := kafkaAnalysis.BaseInfo.PayloadSize
    topic := kafkaAnalysis.Topic

    tcpFlags := formatTCPFlagsFromStruct(kafkaAnalysis.BaseInfo.TCPHeader.FlagNames)
    sequenceNum := kafkaAnalysis.BaseInfo.TCPHeader.SeqNumber
    ttl := kafkaAnalysis.BaseInfo.IPHeader.TTL

    srcPodInfo := formatPodInfoFromProtobuf(enrichedCtx.SrcPod, enrichedCtx.GeoContext, srcIP, srcPort, true)
    var dstPodInfo string
    if enrichedCtx.DstPod != nil {
        dstPodInfo = formatPodInfoFromProtobuf(enrichedCtx.DstPod, enrichedCtx.GeoContext, dstIP, dstPort, false)
    } else {
        dstPodInfo = fmt.Sprintf("external-service(%s:%d)", dstIP, dstPort)
    }

    var latency string
    if len(enrichedCtx.Metrics.RTT) > 0 {
        latency = formatLatencyFromDuration(enrichedCtx.Metrics.RTT)
    }
    uid := extractUIDFromMap(enrichedCtx.SecurityContext)
    capabilities := extractCapabilitiesFromMap(enrichedCtx.SecurityContext)

    var direction string
    if kafkaAnalysis.IsRequest {
        direction = "Request"
    } else {
        direction = "Response"
    }

    var kafkaFields []string
    kafkaFields = append(kafkaFields, direction)
    kafkaFields = append(kafkaFields, apiKeyName)
    kafkaFields = append(kafkaFields, fmt.Sprintf("v%d", apiVersion))
    kafkaFields = append(kafkaFields, fmt.Sprintf("corr:%d", correlationID))
    if topic != "" {
        kafkaFields = append(kafkaFields, fmt.Sprintf("topic:%s", topic))
    }
    kafkaFields = append(kafkaFields, formatBytes(payloadSize))
    if tcpFlags != "" {
        kafkaFields = append(kafkaFields, tcpFlags)
    }

    var protocolInfo []string
    if latency != "" {
        protocolInfo = append(protocolInfo, latency)
    }
    if uid != "" {
        protocolInfo = append(protocolInfo, uid)
    }
    if capabilities != "" {
        protocolInfo = append(protocolInfo, capabilities)
    }
    protocolInfo = append(protocolInfo, fmt.Sprintf("ttl:%d", ttl))
    protocolInfo = append(protocolInfo, fmt.Sprintf("seq:%d", sequenceNum))

    return fmt.Sprintf(`[%s]
%s
=== KAFKA/TCP(%s) ===>
%s`,
        strings.Join(kafkaFields, ", "),
        srcPodInfo,
        strings.Join(protocolInfo, ", "),
        dstPodInfo)
}

// FormatICMPEvent formats ICMP events in the specified format.
func FormatICMPEvent(enrichedCtx *mixer.EnrichedFlowContext, icmpAnalysis *protocol.ICMPAnalysisResult) string {
    srcIP := enrichedCtx.SrcIP
    dstIP := enrichedCtx.DstIP
    srcPort := enrichedCtx.SrcPort
    dstPort := enrichedCtx.DstPort

    typeName := icmpAnalysis.TypeName
    codeName := icmpAnalysis.CodeName
    id := icmpAnalysis.ID
    sequence := icmpAnalysis.Sequence
    payloadSize := icmpAnalysis.BaseInfo.PayloadSize
    ttl := icmpAnalysis.BaseInfo.IPHeader.TTL

    // Message purpose
    var purpose string
    if icmpAnalysis.MessageAnalysis != nil {
        purpose = icmpAnalysis.MessageAnalysis.Purpose
    }

    // OS hint
    var osHint string
    if icmpAnalysis.PingAnalysis != nil {
        osHint = icmpAnalysis.PingAnalysis.OSHint
    }

    srcPodInfo := formatPodInfoFromProtobuf(enrichedCtx.SrcPod, enrichedCtx.GeoContext, srcIP, srcPort, true)
    var dstPodInfo string
    if enrichedCtx.DstPod != nil {
        dstPodInfo = formatPodInfoFromProtobuf(enrichedCtx.DstPod, enrichedCtx.GeoContext, dstIP, dstPort, false)
    } else {
        dstPodInfo = fmt.Sprintf("external(%s:%d)", dstIP, dstPort)
    }

    var latency string
    if len(enrichedCtx.Metrics.RTT) > 0 {
        latency = formatLatencyFromDuration(enrichedCtx.Metrics.RTT)
    }
    uid := extractUIDFromMap(enrichedCtx.SecurityContext)
    capabilities := extractCapabilitiesFromMap(enrichedCtx.SecurityContext)

    var icmpFields []string
    icmpFields = append(icmpFields, typeName)
    icmpFields = append(icmpFields, codeName)
    icmpFields = append(icmpFields, fmt.Sprintf("id:%d", id))
    icmpFields = append(icmpFields, fmt.Sprintf("seq:%d", sequence))
    icmpFields = append(icmpFields, formatBytes(payloadSize))
    if purpose != "" {
        icmpFields = append(icmpFields, purpose)
    }

    var protocolInfo []string
    if latency != "" {
        protocolInfo = append(protocolInfo, latency)
    }
    if uid != "" {
        protocolInfo = append(protocolInfo, uid)
    }
    if capabilities != "" {
        protocolInfo = append(protocolInfo, capabilities)
    }
    protocolInfo = append(protocolInfo, fmt.Sprintf("ttl:%d", ttl))
    if osHint != "" {
        protocolInfo = append(protocolInfo, osHint)
    }

    return fmt.Sprintf(`[%s]
%s
=== ICMP(%s) ===>
%s`,
        strings.Join(icmpFields, ", "),
        srcPodInfo,
        strings.Join(protocolInfo, ", "),
        dstPodInfo)
}

// FormatDNSEvent formats DNS events in the specified format.
func FormatDNSEvent(enrichedCtx *mixer.EnrichedFlowContext, dnsAnalysis *protocol.DNSAnalysisResult) string {
    // Basic network information
    srcIP := enrichedCtx.SrcIP
    dstIP := enrichedCtx.DstIP
    srcPort := enrichedCtx.SrcPort
    dstPort := enrichedCtx.DstPort

    // DNS analysis information
    responseCode := dnsAnalysis.ResponseCodeName
    queryType := dnsAnalysis.QueryTypeName
    queryName := dnsAnalysis.QueryName
    payloadSize := dnsAnalysis.BaseInfo.PayloadSize
    transactionID := dnsAnalysis.TransactionID

    // UDP header information
    udpLength := dnsAnalysis.BaseInfo.UDPHeader.Length

    // IP header information
    ttl := dnsAnalysis.BaseInfo.IPHeader.TTL

    // Extract Pod information
    srcPodInfo := formatPodInfoFromProtobuf(enrichedCtx.SrcPod, enrichedCtx.GeoContext, srcIP, srcPort, true)
    dstPodInfo := formatDNSServerInfoFromGeoContext(dstIP, dstPort, enrichedCtx.GeoContext)

    // Metric information
    var latency string
    if len(enrichedCtx.Metrics.RTT) > 0 {
        latency = formatLatencyFromDuration(enrichedCtx.Metrics.RTT)
    }

    // Security context (map[string]interface{} type)
    uid := extractUIDFromMap(enrichedCtx.SecurityContext)
    capabilities := extractCapabilitiesFromMap(enrichedCtx.SecurityContext)

    // Query purpose
    var purpose string
    if dnsAnalysis.QueryAnalysis != nil {
        purpose = dnsAnalysis.QueryAnalysis.Purpose
    }

    // Construct DNS header information (exclude empty values)
    var dnsFields []string
    if responseCode != "" {
        dnsFields = append(dnsFields, responseCode)
    }
    if queryType != "" {
        dnsFields = append(dnsFields, queryType)
    }
    if queryName != "" {
        dnsFields = append(dnsFields, queryName)
    }
    dnsFields = append(dnsFields, formatBytes(payloadSize))
    dnsFields = append(dnsFields, fmt.Sprintf("txn:%d", transactionID))
    dnsFields = append(dnsFields, fmt.Sprintf("udp:%dB", udpLength))

    // Construct protocol information (exclude empty values)
    var protocolInfo []string
    if latency != "" {
        protocolInfo = append(protocolInfo, latency)
    }
    if uid != "" {
        protocolInfo = append(protocolInfo, uid)
    }
    if capabilities != "" {
        protocolInfo = append(protocolInfo, capabilities)
    }
    protocolInfo = append(protocolInfo, fmt.Sprintf("ttl:%d", ttl))
    if purpose != "" {
        protocolInfo = append(protocolInfo, purpose)
    }

    // Final formatting
    return fmt.Sprintf(`[%s]
%s
=== DNS/UDP(%s) ===>
%s`,
        strings.Join(dnsFields, ", "),
        srcPodInfo,
        strings.Join(protocolInfo, ", "),
        dstPodInfo)
}
