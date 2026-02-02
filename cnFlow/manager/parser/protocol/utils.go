// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package protocol

import (
    "fmt"
    "time"

    "cnFlow/protobuf"
)

// BaseNetworkInfo contains basic network information commonly used by all protocols.
type BaseNetworkInfo struct {
    SrcIP       string `json:"src_ip"`
    DstIP       string `json:"dst_ip"`
    SrcPort     uint32 `json:"src_port"`
    DstPort     uint32 `json:"dst_port"`
    Protocol    string `json:"protocol"`
    PayloadSize uint32 `json:"payload_size"`
    Timestamp   uint64 `json:"timestamp_ns"`

    // IP Header detailed information
    IPHeader    *IPHeaderInfo `json:"ip_header"`

    // TCP/UDP Header information
    TCPHeader   *TCPHeaderInfo `json:"tcp_header,omitempty"`
    UDPHeader   *UDPHeaderInfo `json:"udp_header,omitempty"`
}

type IPHeaderInfo struct {
    TOS         uint32 `json:"tos"`
    TotalLength uint32 `json:"total_length"`
    ID          uint32 `json:"identification"`
    FragOffset  uint32 `json:"fragment_offset"`
    TTL         uint32 `json:"ttl"`
    Protocol    uint32 `json:"protocol"`
    Checksum    uint32 `json:"checksum"`
}

type TCPHeaderInfo struct {
    SeqNumber    uint32   `json:"sequence_number"`
    AckNumber    uint32   `json:"acknowledgment_number"`
    Flags        uint32   `json:"flags"`
    FlagNames    []string `json:"flag_names"`
    WindowSize   uint32   `json:"window_size"`
    Checksum     uint32   `json:"checksum"`
}

type UDPHeaderInfo struct {
    Length   uint32 `json:"length"`
    Checksum uint32 `json:"checksum"`
}

// ParseBaseNetworkInfo extracts common information from BaseNetworkEvent.
func ParseBaseNetworkInfo(base *protobuf.BaseNetworkEvent) *BaseNetworkInfo {
    info := &BaseNetworkInfo{
        SrcIP:       IpToStr(base.SrcAddr),
        DstIP:       IpToStr(base.DstAddr),
        SrcPort:     base.SrcPort,
        DstPort:     base.DstPort,
        Protocol:    GetProtocolName(base.IpProtocol),
        PayloadSize: base.PayloadSize,
        Timestamp:   base.TimestampNs,

        IPHeader: &IPHeaderInfo{
            TOS:         base.IpTos,
            TotalLength: base.IpTotalLen,
            ID:          base.IpId,
            FragOffset:  base.IpFragOff,
            TTL:         base.IpTtl,
            Protocol:    base.IpProtocol,
            Checksum:    base.IpCheck,
        },
    }

    // TCP Header information
    if base.IpProtocol == 6 {
        info.TCPHeader = &TCPHeaderInfo{
            SeqNumber:  base.Seq,
            AckNumber:  base.AckSeq,
            Flags:      base.TcpFlags,
            FlagNames:  FormatTCPFlags(base.TcpFlags),
            WindowSize: base.Window,
            Checksum:   base.TcpCheck,
        }
    }

    // UDP Header information
    if base.IpProtocol == 17 {
        info.UDPHeader = &UDPHeaderInfo{
            Length:   base.UdpLen,
            Checksum: base.UdpCheck,
        }
    }

    return info
}

// IpToStr converts a 32-bit IP address to dotted-decimal notation.
func IpToStr(ip uint32) string {
    return fmt.Sprintf("%d.%d.%d.%d",
        byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

// FormatTimestamp formats a nanosecond timestamp to human-readable format.
func FormatTimestamp(timestampNs uint64) string {
    t := time.Unix(0, int64(timestampNs))
    return fmt.Sprintf("Boot+%s", t.Format("15:04:05.000000000"))
}

// FormatTCPFlags converts TCP flags to a slice of flag names.
func FormatTCPFlags(flags uint32) []string {
    var flagStrs []string
    if flags&0x01 != 0 { flagStrs = append(flagStrs, "FIN") }
    if flags&0x02 != 0 { flagStrs = append(flagStrs, "SYN") }
    if flags&0x04 != 0 { flagStrs = append(flagStrs, "RST") }
    if flags&0x08 != 0 { flagStrs = append(flagStrs, "PSH") }
    if flags&0x10 != 0 { flagStrs = append(flagStrs, "ACK") }
    if flags&0x20 != 0 { flagStrs = append(flagStrs, "URG") }
    return flagStrs
}

// GetProtocolName returns the protocol name for a protocol number.
func GetProtocolName(protocol uint32) string {
    switch protocol {
    case 1: return "ICMP"
    case 6: return "TCP"
    case 17: return "UDP"
    default: return fmt.Sprintf("Protocol%d", protocol)
    }
}

// ParseInt parses a string to an integer.
func ParseInt(s string) int {
    result := 0
    for _, char := range s {
        if char >= '0' && char <= '9' {
            result = result*10 + int(char-'0')
        } else {
            return 0
        }
    }
    return result
}

// TruncateString truncates a string to the specified length and adds "...".
func TruncateString(s string, maxLen int) string {
    if len(s) <= maxLen {
        return s
    }
    return s[:maxLen] + "..."
}
