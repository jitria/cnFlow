// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package protocol

import (
    "fmt"

    "cnFlow/protobuf"
)

// ICMPAnalysisResult contains all analysis results from an ICMP event.
type ICMPAnalysisResult struct {
    // Basic network information
    BaseInfo *BaseNetworkInfo `json:"base_info"`

    // ICMP protocol information
    Type        uint32 `json:"type"`
    TypeName    string `json:"type_name"`
    Code        uint32 `json:"code"`
    CodeName    string `json:"code_name"`
    ID          uint32 `json:"id"`
    Sequence    uint32 `json:"sequence"`

    // Detailed analysis by ICMP type
    MessageAnalysis *ICMPMessageAnalysis `json:"message_analysis"`

    // Ping pattern analysis (for Echo Request/Reply)
    PingAnalysis *ICMPPingAnalysis `json:"ping_analysis,omitempty"`
}

type ICMPMessageAnalysis struct {
    Purpose     string `json:"purpose"`
    Direction   string `json:"direction"`
    Status      string `json:"status,omitempty"`
    Issue       string `json:"issue,omitempty"`
    Cause       string `json:"cause,omitempty"`
    Action      string `json:"action,omitempty"`
    Usage       string `json:"usage,omitempty"`
    Note        string `json:"note,omitempty"`
}

type ICMPPingAnalysis struct {
    ToolType    string `json:"tool_type"`
    Pattern     string `json:"pattern"`
    OSHint      string `json:"os_hint"`
    TTLValue    uint32 `json:"ttl_value"`
}

// AnalyzeICMPEventDetailed analyzes an ICMP event and returns all results.
func AnalyzeICMPEventDetailed(event *protobuf.ICMPEvent) *ICMPAnalysisResult {
    result := &ICMPAnalysisResult{
        // Basic network information
        BaseInfo: ParseBaseNetworkInfo(event.Base),

        // ICMP protocol information
        Type:     event.Type,
        TypeName: GetICMPTypeName(event.Type),
        Code:     event.Code,
        CodeName: GetICMPCodeDescription(event.Type, event.Code),
        ID:       event.Id,
        Sequence: event.Sequence,

        // Detailed analysis by ICMP type
        MessageAnalysis: analyzeICMPMessageByType(event),
    }

    // Add ping pattern analysis for Echo Request/Reply
    if event.Type == 8 || event.Type == 0 {
        result.PingAnalysis = analyzeICMPPingPattern(event)
    }

    return result
}

// ProcessICMPEventDetailed is kept for backward compatibility (no log output).
func ProcessICMPEventDetailed(event *protobuf.ICMPEvent) {
    // This function no longer outputs logs
    // Use AnalyzeICMPEventDetailed if needed
}

// analyzeICMPMessageByType analyzes an ICMP message based on its type and code.
func analyzeICMPMessageByType(event *protobuf.ICMPEvent) *ICMPMessageAnalysis {
    analysis := &ICMPMessageAnalysis{
        Direction: fmt.Sprintf("%s -> %s", 
            IpToStr(event.Base.SrcAddr), IpToStr(event.Base.DstAddr)),
    }
    
    switch event.Type {
    case 0: // Echo Reply
        analysis.Purpose = "Connectivity confirmation"
        analysis.Status = "Successful ping response"
    case 3: // Destination Unreachable
        analysis.Purpose = "Network/Host unreachability notification"
        analysis = analyzeDestinationUnreachable(analysis, event.Code)
    case 4: // Source Quench
        analysis.Purpose = "Flow control notification"
        analysis.Issue = "Congestion control request"
        analysis.Action = "Sender should reduce transmission rate"
        analysis.Note = "Deprecated in modern networks"
    case 5: // Redirect
        analysis.Purpose = "Route optimization notification"
        analysis = analyzeRedirect(analysis, event.Code)
    case 8: // Echo Request
        analysis.Purpose = "Connectivity test"
        analysis.Status = "Ping request"
    case 11: // Time Exceeded
        analysis.Purpose = "TTL/Hop limit exceeded notification"
        analysis = analyzeTimeExceeded(analysis, event.Code)
    case 12: // Parameter Problem
        analysis.Purpose = "IP header error notification"
        analysis.Issue = "Malformed IP header"
        analysis.Note = fmt.Sprintf("Pointer: Byte %d in original header", event.Code)
    case 13: // Timestamp Request
        analysis.Purpose = "Time synchronization request"
        analysis.Status = "Expected Response: Timestamp Reply (Type 14)"
    case 14: // Timestamp Reply
        analysis.Purpose = "Time synchronization response"
        analysis.Note = "Contains originate, receive, transmit timestamps"
    case 15: // Information Request
        analysis.Purpose = "Network information request"
        analysis.Note = "Obsolete, replaced by DHCP"
    case 16: // Information Reply
        analysis.Purpose = "Network information response"
        analysis.Note = "Obsolete, replaced by DHCP"
    case 17: // Address Mask Request
        analysis.Purpose = "Subnet mask discovery"
        analysis.Status = "Expected Response: Address Mask Reply (Type 18)"
    case 18: // Address Mask Reply
        analysis.Purpose = "Subnet mask information"
        analysis.Note = "Contains subnet mask information"
    default:
        analysis.Purpose = "Non-standard or experimental ICMP type"
        analysis.Note = fmt.Sprintf("Unknown ICMP type %d", event.Type)
    }
    
    return analysis
}

// analyzeDestinationUnreachable adds detail for Destination Unreachable codes.
func analyzeDestinationUnreachable(analysis *ICMPMessageAnalysis, code uint32) *ICMPMessageAnalysis {
    switch code {
    case 0:
        analysis.Issue = "Network is unreachable"
        analysis.Cause = "No route to destination network"
    case 1:
        analysis.Issue = "Host is unreachable"
        analysis.Cause = "Host not responding or down"
    case 2:
        analysis.Issue = "Protocol unreachable"
        analysis.Cause = "Protocol not supported"
    case 3:
        analysis.Issue = "Port unreachable"
        analysis.Cause = "No service listening on port"
    case 4:
        analysis.Issue = "Fragmentation needed but DF set"
        analysis.Cause = "MTU discovery issue"
    case 5:
        analysis.Issue = "Source route failed"
        analysis.Cause = "Source routing problem"
    default:
        analysis.Issue = "Other unreachability reason"
    }
    return analysis
}

// analyzeTimeExceeded adds detail for Time Exceeded codes.
func analyzeTimeExceeded(analysis *ICMPMessageAnalysis, code uint32) *ICMPMessageAnalysis {
    switch code {
    case 0:
        analysis.Issue = "TTL exceeded in transit"
        analysis.Cause = "Packet TTL reached 0 during forwarding"
        analysis.Usage = "Traceroute detection"
    case 1:
        analysis.Issue = "Fragment reassembly time exceeded"
        analysis.Cause = "Fragment timeout during reassembly"
    default:
        analysis.Issue = "Other time exceeded reason"
    }
    return analysis
}

// analyzeRedirect adds detail for ICMP Redirect codes.
func analyzeRedirect(analysis *ICMPMessageAnalysis, code uint32) *ICMPMessageAnalysis {
    switch code {
    case 0:
        analysis.Status = "Redirect for network"
    case 1:
        analysis.Status = "Redirect for host"
    case 2:
        analysis.Status = "Redirect for TOS and network"
    case 3:
        analysis.Status = "Redirect for TOS and host"
    }
    return analysis
}

// analyzeICMPPingPattern analyzes ping patterns including tool type and OS hints.
func analyzeICMPPingPattern(event *protobuf.ICMPEvent) *ICMPPingAnalysis {
    analysis := &ICMPPingAnalysis{
        TTLValue: event.Base.IpTtl,
    }

    // Identify common ping tools
    if event.Id == 0 {
        analysis.ToolType = "Custom ping implementation"
    } else {
        analysis.ToolType = "Standard ping utility"
    }

    // Sequence number pattern
    if event.Sequence == 1 {
        analysis.Pattern = "First ping in sequence"
    } else if event.Sequence > 1 {
        analysis.Pattern = fmt.Sprintf("Ping #%d in sequence", event.Sequence)
    }

    // TTL analysis
    ttl := event.Base.IpTtl
    if ttl == 64 {
        analysis.OSHint = "Likely Linux/Unix (TTL 64)"
    } else if ttl == 128 {
        analysis.OSHint = "Likely Windows (TTL 128)"
    } else if ttl == 255 {
        analysis.OSHint = "Likely Cisco/Network device (TTL 255)"
    } else {
        analysis.OSHint = fmt.Sprintf("Custom TTL value (%d)", ttl)
    }

    return analysis
}

// GetICMPTypeName returns the name of an ICMP type.
func GetICMPTypeName(icmpType uint32) string {
    switch icmpType {
    case 0: return "Echo Reply"
    case 3: return "Destination Unreachable"
    case 4: return "Source Quench"
    case 5: return "Redirect"
    case 8: return "Echo Request"
    case 11: return "Time Exceeded"
    case 12: return "Parameter Problem"
    case 13: return "Timestamp Request"
    case 14: return "Timestamp Reply"
    case 15: return "Information Request"
    case 16: return "Information Reply"
    case 17: return "Address Mask Request"
    case 18: return "Address Mask Reply"
    default: return fmt.Sprintf("Type%d", icmpType)
    }
}

// GetICMPCodeDescription returns the description of an ICMP code.
func GetICMPCodeDescription(icmpType, code uint32) string {
    switch icmpType {
    case 3: // Destination Unreachable
        return getDestUnreachableCode(code)
    case 5: // Redirect
        return getRedirectCode(code)
    case 11: // Time Exceeded
        return getTimeExceededCode(code)
    default:
        if code == 0 {
            return "Standard"
        }
        return fmt.Sprintf("Code%d", code)
    }
}

// getDestUnreachableCode returns the description for a Destination Unreachable code.
func getDestUnreachableCode(code uint32) string {
    switch code {
    case 0: return "Network Unreachable"
    case 1: return "Host Unreachable"
    case 2: return "Protocol Unreachable"
    case 3: return "Port Unreachable"
    case 4: return "Fragmentation Needed"
    case 5: return "Source Route Failed"
    case 6: return "Destination Network Unknown"
    case 7: return "Destination Host Unknown"
    case 8: return "Source Host Isolated"
    case 9: return "Network Administratively Prohibited"
    case 10: return "Host Administratively Prohibited"
    case 11: return "Network Unreachable for TOS"
    case 12: return "Host Unreachable for TOS"
    case 13: return "Communication Administratively Prohibited"
    case 14: return "Host Precedence Violation"
    case 15: return "Precedence Cutoff"
    default: return fmt.Sprintf("Code%d", code)
    }
}

// getRedirectCode returns the description for an ICMP Redirect code.
func getRedirectCode(code uint32) string {
    switch code {
    case 0: return "Redirect for Network"
    case 1: return "Redirect for Host"
    case 2: return "Redirect for TOS and Network"
    case 3: return "Redirect for TOS and Host"
    default: return fmt.Sprintf("Code%d", code)
    }
}

// getTimeExceededCode returns the description for a Time Exceeded code.
func getTimeExceededCode(code uint32) string {
    switch code {
    case 0: return "TTL Exceeded in Transit"
    case 1: return "Fragment Reassembly Time Exceeded"
    default: return fmt.Sprintf("Code%d", code)
    }
}
