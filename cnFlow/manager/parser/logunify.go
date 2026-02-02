// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package parser

import (
    "log"
    "fmt"
    "strings"
    "time"

    jprotocol "cnFlow/manager/parser/protocol"
    "cnFlow/manager/mixer"
)

// logUnifiedAnalysis logs unified protocol analysis results.
func logUnifiedAnalysis(enrichedCtx *mixer.EnrichedFlowContext, protocolAnalysis interface{}, protocol string) {
    if enrichedCtx == nil {
        return
    }

    switch protocol {
    case "HTTP", "HTTP2":
        logHTTPUnified(enrichedCtx, protocolAnalysis, protocol)
    case "DNS":
        logDNSUnified(enrichedCtx, protocolAnalysis)
    case "Redis":
        logRedisUnified(enrichedCtx, protocolAnalysis)
    case "Kafka":
        logKafkaUnified(enrichedCtx, protocolAnalysis)
    case "ICMP":
        logICMPUnified(enrichedCtx, protocolAnalysis)
    }
}

// logHTTPUnified logs unified HTTP/HTTP2 analysis results.
func logHTTPUnified(enrichedCtx *mixer.EnrichedFlowContext, analysis interface{}, protocol string) {
    httpAnalysis, ok := analysis.(*jprotocol.HTTPAnalysisResult)
    if !ok {
        return
    }

    var protocolInfo string

    if httpAnalysis.IsRequest {
        path := httpAnalysis.URI
        if path == "" {
            path = "/"
        }
        protocolInfo = fmt.Sprintf("[%s, %s]",
            httpAnalysis.Method,
            path)
    } else {
        statusText := httpAnalysis.StatusCode
        if httpAnalysis.ResponseAnalysis != nil && httpAnalysis.ResponseAnalysis.StatusText != "" {
            statusText = httpAnalysis.ResponseAnalysis.StatusText
        }
        protocolInfo = fmt.Sprintf("[%s, %s]",
            httpAnalysis.StatusCode,
            statusText)
    }

    srcInfo := formatSourceInfo(enrichedCtx)
    dstInfo := formatDestinationInfo(enrichedCtx)
    connectionInfo := formatConnectionInfo(enrichedCtx, protocol)

    log.Printf("%s\n%s\n%s\n%s",
        protocolInfo,
        srcInfo,
        connectionInfo,
        dstInfo)
}

// logDNSUnified logs unified DNS analysis results.
func logDNSUnified(enrichedCtx *mixer.EnrichedFlowContext, analysis interface{}) {
    dnsAnalysis, ok := analysis.(*jprotocol.DNSAnalysisResult)
    if !ok {
        return
    }

    var protocolInfo string

    if dnsAnalysis.IsQuery {
        protocolInfo = fmt.Sprintf("[QUERY, %s, %s]",
            dnsAnalysis.QueryTypeName,
            dnsAnalysis.QueryName)
    } else {
        protocolInfo = fmt.Sprintf("[%s, %s, %s]",
            dnsAnalysis.ResponseCodeName,
            dnsAnalysis.QueryTypeName,
            dnsAnalysis.QueryName)
    }

    srcInfo := formatSourceInfo(enrichedCtx)
    dstInfo := formatDestinationInfo(enrichedCtx)
    connectionInfo := formatConnectionInfo(enrichedCtx, "DNS")

    log.Printf("%s\n%s\n%s\n%s",
        protocolInfo,
        srcInfo,
        connectionInfo,
        dstInfo)
}

// logRedisUnified logs unified Redis analysis results.
func logRedisUnified(enrichedCtx *mixer.EnrichedFlowContext, analysis interface{}) {
    redisAnalysis, ok := analysis.(*jprotocol.RedisAnalysisResult)
    if !ok {
        return
    }

    var protocolInfo string

    if redisAnalysis.IsRequest {
        key := ""
        if redisAnalysis.KeyValueInfo != nil {
            if redisAnalysis.KeyValueInfo.Key != "" {
                key = redisAnalysis.KeyValueInfo.Key
            } else if redisAnalysis.KeyValueInfo.Hash != "" {
                key = redisAnalysis.KeyValueInfo.Hash
            } else if redisAnalysis.KeyValueInfo.Set != "" {
                key = redisAnalysis.KeyValueInfo.Set
            } else if len(redisAnalysis.KeyValueInfo.ExtractedValues) > 0 {
                key = redisAnalysis.KeyValueInfo.ExtractedValues[0]
            }
        }

        if key == "" {
            key = "unknown"
        }

        protocolInfo = fmt.Sprintf("[%s, %s]",
            redisAnalysis.CommandName,
            key)
    } else {
        responseType := redisAnalysis.RespTypeName
        content := ""

        if redisAnalysis.ResponseAnalysis != nil {
            if redisAnalysis.ResponseAnalysis.Result != "" {
                content = redisAnalysis.ResponseAnalysis.Result
            } else if redisAnalysis.ResponseAnalysis.Content != "" {
                content = redisAnalysis.ResponseAnalysis.Content
            } else {
                content = redisAnalysis.ResponseAnalysis.Type
            }
        }

        if content == "" {
            content = "response"
        }

        protocolInfo = fmt.Sprintf("[%s, %s]",
            responseType,
            content)
    }

    srcInfo := formatSourceInfo(enrichedCtx)
    dstInfo := formatDestinationInfo(enrichedCtx)
    connectionInfo := formatConnectionInfo(enrichedCtx, "REDIS")

    log.Printf("%s\n%s\n%s\n%s",
        protocolInfo,
        srcInfo,
        connectionInfo,
        dstInfo)
}

// logKafkaUnified logs unified Kafka analysis results.
func logKafkaUnified(enrichedCtx *mixer.EnrichedFlowContext, analysis interface{}) {
    kafkaAnalysis, ok := analysis.(*jprotocol.KafkaAnalysisResult)
    if !ok {
        return
    }

    var protocolInfo string

    if kafkaAnalysis.IsRequest {
        topic := kafkaAnalysis.Topic
        if topic == "" {
            topic = "unknown-topic"
        }

        clientInfo := fmt.Sprintf("client-%d", kafkaAnalysis.CorrelationID)

        protocolInfo = fmt.Sprintf("[%s, %s, %s]",
            kafkaAnalysis.ApiKeyName,
            topic,
            clientInfo)
    } else {
        topic := kafkaAnalysis.Topic
        if topic == "" {
            topic = "unknown-topic"
        }

        protocolInfo = fmt.Sprintf("[%sResponse, %s, corr:%d]",
            kafkaAnalysis.ApiKeyName,
            topic,
            kafkaAnalysis.CorrelationID)
    }

    srcInfo := formatSourceInfo(enrichedCtx)
    dstInfo := formatDestinationInfo(enrichedCtx)
    connectionInfo := formatConnectionInfo(enrichedCtx, "KAFKA")

    log.Printf("%s\n%s\n%s\n%s",
        protocolInfo,
        srcInfo,
        connectionInfo,
        dstInfo)
}

// logICMPUnified logs unified ICMP analysis results.
func logICMPUnified(enrichedCtx *mixer.EnrichedFlowContext, analysis interface{}) {
    icmpAnalysis, ok := analysis.(*jprotocol.ICMPAnalysisResult)
    if !ok {
        return
    }

    var protocolInfo string

    switch icmpAnalysis.Type {
    case 0:
        protocolInfo = fmt.Sprintf("[Echo Reply, %d, %d:%d]",
            icmpAnalysis.Code,
            icmpAnalysis.ID,
            icmpAnalysis.Sequence)
    case 8:
        protocolInfo = fmt.Sprintf("[Echo Request, %d, %d:%d]",
            icmpAnalysis.Code,
            icmpAnalysis.ID,
            icmpAnalysis.Sequence)
    case 3:
        protocolInfo = fmt.Sprintf("[Dest Unreachable, %s]",
            icmpAnalysis.CodeName)
    case 11:
        protocolInfo = fmt.Sprintf("[Time Exceeded, %s]",
            icmpAnalysis.CodeName)
    default:
        protocolInfo = fmt.Sprintf("[%s, %d]",
            icmpAnalysis.TypeName,
            icmpAnalysis.Code)
    }

    srcInfo := formatSourceInfo(enrichedCtx)
    dstInfo := formatDestinationInfo(enrichedCtx)
    connectionInfo := formatConnectionInfo(enrichedCtx, "ICMP")

    log.Printf("%s\n%s\n%s\n%s",
        protocolInfo,
        srcInfo,
        connectionInfo,
        dstInfo)
}

// formatSourceInfo formats source information from the enriched context.
func formatSourceInfo(enrichedCtx *mixer.EnrichedFlowContext) string {
    var podName, region, country string

    if enrichedCtx.SrcPod != nil {
        podName = enrichedCtx.SrcPod.Name
    } else {
        podName = enrichedCtx.SrcIP
    }

    if enrichedCtx.GeoContext != nil && enrichedCtx.GeoContext.SourceGeo != nil {
        region = enrichedCtx.GeoContext.SourceGeo.Region
        country = enrichedCtx.GeoContext.SourceGeo.Country
    }

    if region == "" {
        region = "unknown-region"
    }
    if country == "" {
        country = "XX"
    }

    return fmt.Sprintf("%s(%s, %s)", podName, region, country)
}

// formatDestinationInfo formats destination information from the enriched context.
func formatDestinationInfo(enrichedCtx *mixer.EnrichedFlowContext) string {
    var podName, region, country string

    if enrichedCtx.DstPod != nil {
        podName = enrichedCtx.DstPod.Name
    } else {
        podName = enrichedCtx.DstIP
    }

    if enrichedCtx.GeoContext != nil && enrichedCtx.GeoContext.DestinationGeo != nil {
        region = enrichedCtx.GeoContext.DestinationGeo.Region
        country = enrichedCtx.GeoContext.DestinationGeo.Country
    }

    if region == "" {
        region = "unknown-region"
    }
    if country == "" {
        country = "XX"
    }

    return fmt.Sprintf("%s(%s, %s)", podName, region, country)
}

// formatConnectionInfo formats connection information from the enriched context.
func formatConnectionInfo(enrichedCtx *mixer.EnrichedFlowContext, protocol string) string {
    var rtt string = "0ms"
    var securityInfo string = "N/A"

    if enrichedCtx.Metrics != nil {
        metrics := enrichedCtx.Metrics.GetMetricsSummary()
        if avgRTT, ok := metrics["avg_rtt"].(time.Duration); ok && avgRTT > 0 {
            rtt = fmt.Sprintf("%.1fms", float64(avgRTT.Nanoseconds())/1e6)
        }
    }

    securityInfo = extractSecurityInfo(enrichedCtx)

    return fmt.Sprintf("=== %s(%s, %s) ===>", protocol, rtt, securityInfo)
}

// extractSecurityInfo extracts security information from the enriched context.
func extractSecurityInfo(enrichedCtx *mixer.EnrichedFlowContext) string {
    if enrichedCtx.SecurityContext == nil {
        return "N/A"
    }

    var securityFeatures []string

    if srcSecurity, ok := enrichedCtx.SecurityContext["source"].(map[string]interface{}); ok {
        securityFeatures = append(securityFeatures, extractPodSecurityInfo(srcSecurity)...)
    }

    if dstSecurity, ok := enrichedCtx.SecurityContext["destination"].(map[string]interface{}); ok {
        securityFeatures = append(securityFeatures, extractPodSecurityInfo(dstSecurity)...)
    }

    if len(securityFeatures) == 0 {
        return "N/A"
    }

    uniqueFeatures := removeDuplicates(securityFeatures)
    if len(uniqueFeatures) > 2 {
        uniqueFeatures = uniqueFeatures[:2]
    }

    return strings.Join(uniqueFeatures, ",")
}

// extractPodSecurityInfo extracts security information from a pod's security context.
func extractPodSecurityInfo(security map[string]interface{}) []string {
    var features []string

    if privileged, ok := security["privileged_mode"].(bool); ok && privileged {
        features = append(features, "priv")
    } else {
        features = append(features, "!priv")
    }

    if runsAsRoot, ok := security["runs_as_root"].(bool); ok && !runsAsRoot {
        if uid, ok := security["run_as_user"].(int64); ok {
            features = append(features, fmt.Sprintf("uid:%d", uid))
        }
    }

    if readOnlyRoot, ok := security["read_only_root_filesystem"].(bool); ok && readOnlyRoot {
        features = append(features, "ro")
    }

    if caps, ok := security["dropped_capabilities"].([]string); ok && len(caps) > 0 {
        if contains(caps, "ALL") {
            features = append(features, "capabilities:drop[ALL]")
        }
    }

    if seccompProfile, ok := security["seccomp_profile"].(string); ok && seccompProfile != "" {
        features = append(features, fmt.Sprintf("seccompProfile:%s", seccompProfile))
    }

    if allowEscalation, ok := security["allows_privilege_escalation"].(bool); ok && !allowEscalation {
        features = append(features, "allowPrivilegeEscalation:false")
    }

    if fsGroup, ok := security["fs_group"].(int64); ok && fsGroup > 0 {
        features = append(features, fmt.Sprintf("fsGroup:%d", fsGroup))
    }

    return features
}

// removeDuplicates removes duplicate strings from a slice.
func removeDuplicates(slice []string) []string {
    keys := make(map[string]bool)
    var result []string

    for _, item := range slice {
        if !keys[item] {
            keys[item] = true
            result = append(result, item)
        }
    }
    return result
}

// contains checks if a slice contains a specific string.
func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}
