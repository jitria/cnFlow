// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package protocol

import (
    "fmt"
    "strings"

    "cnFlow/protobuf"
)

// DNSAnalysisResult contains all analysis results from a DNS event.
type DNSAnalysisResult struct {
    // Basic network information
    BaseInfo *BaseNetworkInfo `json:"base_info"`

    // DNS protocol information
    TransactionID    uint32 `json:"transaction_id"`
    QueryType        uint32 `json:"query_type"`
    QueryTypeName    string `json:"query_type_name"`
    QueryName        string `json:"query_name"`
    ResponseCode     uint32 `json:"response_code"`
    ResponseCodeName string `json:"response_code_name"`
    IsQuery          bool   `json:"is_query"`

    // Detailed analysis by query/response
    QueryAnalysis    *DNSQueryAnalysis    `json:"query_analysis,omitempty"`
    ResponseAnalysis *DNSResponseAnalysis `json:"response_analysis,omitempty"`

    // Domain analysis
    DomainAnalysis   *DNSDomainAnalysis   `json:"domain_analysis"`
}

type DNSQueryAnalysis struct {
    Purpose          string `json:"purpose"`
    Target           string `json:"target"`
    ExpectedResponse string `json:"expected_response"`
}

type DNSResponseAnalysis struct {
    Result string `json:"result"`
    Action string `json:"action,omitempty"`
    Issue  string `json:"issue,omitempty"`
}

type DNSDomainAnalysis struct {
    FullDomain    string            `json:"full_domain"`
    Length        int               `json:"length"`
    DomainLevels  int               `json:"domain_levels"`
    TLD           string            `json:"tld,omitempty"`
    SecondLevel   string            `json:"second_level,omitempty"`
    Subdomains    string            `json:"subdomains,omitempty"`
    DomainType    string            `json:"domain_type"`
    ReverseDNS    *DNSReverseDNSInfo `json:"reverse_dns,omitempty"`
}

type DNSReverseDNSInfo struct {
    IsReverse bool   `json:"is_reverse"`
    IsIPv6    bool   `json:"is_ipv6"`
    IPAddress string `json:"ip_address,omitempty"`
}

// AnalyzeDNSEventDetailed analyzes a DNS event and returns all results.
func AnalyzeDNSEventDetailed(event *protobuf.DNSEvent) *DNSAnalysisResult {
    result := &DNSAnalysisResult{
        // Basic network information
        BaseInfo: ParseBaseNetworkInfo(event.Base),

        // DNS protocol information
        TransactionID:    event.TransactionId,
        QueryType:        event.QueryType,
        QueryTypeName:    GetDNSTypeName(event.QueryType),
        QueryName:        event.QueryName,
        ResponseCode:     event.ResponseCode,
        ResponseCodeName: GetDNSResponseCode(event.ResponseCode),
        IsQuery:          event.IsQuery,

        // Domain analysis
        DomainAnalysis: analyzeDNSDomainComponents(event.QueryName),
    }

    // Detailed analysis by query/response
    if event.IsQuery {
        result.QueryAnalysis = analyzeDNSQueryType(event.QueryType, event.QueryName)
    } else {
        result.ResponseAnalysis = analyzeDNSResponseCode(event.ResponseCode, event.QueryName)
    }

    return result
}

// ProcessDNSEventDetailed is kept for backward compatibility (no log output).
func ProcessDNSEventDetailed(event *protobuf.DNSEvent) {
    // This function no longer outputs logs
    // Use AnalyzeDNSEventDetailed if needed
}

// analyzeDNSQueryType determines the purpose of a DNS query based on its type.
func analyzeDNSQueryType(queryType uint32, queryName string) *DNSQueryAnalysis {
    analysis := &DNSQueryAnalysis{
        Target: queryName,
    }
    
    switch queryType {
    case 1: // A
        analysis.Purpose = "IPv4 address lookup"
        analysis.ExpectedResponse = "IPv4 address (32-bit)"
    case 28: // AAAA
        analysis.Purpose = "IPv6 address lookup"
        analysis.ExpectedResponse = "IPv6 address (128-bit)"
    case 15: // MX
        analysis.Purpose = "Mail exchange server lookup"
        analysis.ExpectedResponse = "Mail server hostname and priority"
    case 2: // NS
        analysis.Purpose = "Name server lookup"
        analysis.ExpectedResponse = "Authoritative name servers"
    case 5: // CNAME
        analysis.Purpose = "Canonical name lookup"
        analysis.ExpectedResponse = "Canonical domain name"
    case 12: // PTR
        analysis.Purpose = "Reverse DNS lookup"
        analysis.ExpectedResponse = "Domain name for IP address"
    case 16: // TXT
        analysis.Purpose = "Text record lookup"
        analysis.ExpectedResponse = "Text information (SPF, DKIM, etc.)"
    case 6: // SOA
        analysis.Purpose = "Start of Authority lookup"
        analysis.ExpectedResponse = "Zone authority information"
    case 33: // SRV
        analysis.Purpose = "Service record lookup"
        analysis.ExpectedResponse = "Service location (host, port, priority)"
    case 255: // ANY
        analysis.Purpose = "All available records"
        analysis.ExpectedResponse = "All record types for domain"
    default:
        analysis.Purpose = "Custom or experimental record type"
        analysis.ExpectedResponse = "Unknown"
    }
    
    return analysis
}

// analyzeDNSResponseCode interprets the DNS response code.
func analyzeDNSResponseCode(responseCode uint32, queryName string) *DNSResponseAnalysis {
    analysis := &DNSResponseAnalysis{}
    
    switch responseCode {
    case 0: // NOERROR
        analysis.Result = "Successful resolution"
        analysis.Action = "Response contains requested records"
    case 1: // FORMERR
        analysis.Result = "Format error in query"
        analysis.Issue = "Malformed DNS query packet"
    case 2: // SERVFAIL
        analysis.Result = "Server failure"
        analysis.Issue = "DNS server unable to process query"
    case 3: // NXDOMAIN
        analysis.Result = "Domain does not exist"
        analysis.Action = "Domain name does not exist in DNS"
    case 4: // NOTIMP
        analysis.Result = "Query type not implemented"
        analysis.Issue = "Server does not support this query type"
    case 5: // REFUSED
        analysis.Result = "Query refused"
        analysis.Issue = "Server policy refuses to answer"
    case 6: // YXDOMAIN
        analysis.Result = "Domain exists when it should not"
    case 7: // YXRRSET
        analysis.Result = "RR set exists when it should not"
    case 8: // NXRRSET
        analysis.Result = "RR set does not exist"
    case 9: // NOTAUTH
        analysis.Result = "Server not authoritative"
    case 10: // NOTZONE
        analysis.Result = "Name not in zone"
    default:
        analysis.Result = "Unknown response code"
    }
    
    return analysis
}

// analyzeDNSDomainComponents breaks a domain name into its structural components.
func analyzeDNSDomainComponents(queryName string) *DNSDomainAnalysis {
    analysis := &DNSDomainAnalysis{
        FullDomain: queryName,
        Length:     len(queryName),
    }
    
    if queryName == "" {
        analysis.DomainType = "empty"
        return analysis
    }

    // Analyze domain levels
    parts := strings.Split(queryName, ".")
    analysis.DomainLevels = len(parts)

    if len(parts) > 1 {
        // TLD (Top Level Domain)
        if parts[len(parts)-1] != "" {
            analysis.TLD = parts[len(parts)-1]
        }

        // Second Level Domain
        if len(parts) > 1 && parts[len(parts)-2] != "" {
            analysis.SecondLevel = parts[len(parts)-2]
        }

        // Subdomain
        if len(parts) > 2 {
            subdomains := parts[:len(parts)-2]
            if len(subdomains) > 0 {
                analysis.Subdomains = strings.Join(subdomains, ".")
            }
        }

        analysis.DomainType = "multi_level"
    } else {
        analysis.DomainType = "single_label"
    }

    // Analyze reverse DNS (pure parsing)
    analysis.ReverseDNS = analyzeReverseDNS(queryName)
    
    return analysis
}

// analyzeReverseDNS checks if a query name is a reverse DNS lookup and extracts the IP.
func analyzeReverseDNS(queryName string) *DNSReverseDNSInfo {
    reverseDNS := &DNSReverseDNSInfo{}
    
    if strings.HasSuffix(queryName, ".in-addr.arpa") {
        reverseDNS.IsReverse = true
        reverseDNS.IsIPv6 = false
        
        reversePart := strings.TrimSuffix(queryName, ".in-addr.arpa")
        octets := strings.Split(reversePart, ".")
        if len(octets) == 4 {
            reverseDNS.IPAddress = fmt.Sprintf("%s.%s.%s.%s", octets[3], octets[2], octets[1], octets[0])
        }
    } else if strings.HasSuffix(queryName, ".ip6.arpa") {
        reverseDNS.IsReverse = true
        reverseDNS.IsIPv6 = true
        reversePart := strings.TrimSuffix(queryName, ".ip6.arpa")
        reverseDNS.IPAddress = reversePart
    }
    
    if !reverseDNS.IsReverse {
        return nil
    }
    
    return reverseDNS
}

// GetDNSTypeName returns the name of a DNS query type.
func GetDNSTypeName(dnsType uint32) string {
    switch dnsType {
    case 1: return "A"
    case 2: return "NS"
    case 5: return "CNAME"
    case 6: return "SOA"
    case 12: return "PTR"
    case 15: return "MX"
    case 16: return "TXT"
    case 28: return "AAAA"
    case 33: return "SRV"
    case 35: return "NAPTR"
    case 39: return "DNAME"
    case 43: return "DS"
    case 46: return "RRSIG"
    case 47: return "NSEC"
    case 48: return "DNSKEY"
    case 255: return "ANY"
    default: return fmt.Sprintf("TYPE%d", dnsType)
    }
}

// GetDNSResponseCode returns the name of a DNS response code.
func GetDNSResponseCode(rcode uint32) string {
    switch rcode {
    case 0: return "NOERROR"
    case 1: return "FORMERR"
    case 2: return "SERVFAIL"
    case 3: return "NXDOMAIN"
    case 4: return "NOTIMP"
    case 5: return "REFUSED"
    case 6: return "YXDOMAIN"
    case 7: return "YXRRSET"
    case 8: return "NXRRSET"
    case 9: return "NOTAUTH"
    case 10: return "NOTZONE"
    default: return fmt.Sprintf("RCODE%d", rcode)
    }
}
