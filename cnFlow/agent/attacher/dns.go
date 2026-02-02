// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package attacher

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "log"

    "cnFlow/types"
    "cnFlow/agent/uploader"
)

// processDNSEvent parses a raw ring buffer sample into a DNS event and forwards it to the manager.
func processDNSEvent(rawData []byte) error {
    var dnsData TCDnsEvent

    if err := binary.Read(bytes.NewBuffer(rawData), binary.LittleEndian, &dnsData); err != nil {
        return fmt.Errorf("failed to parse DNS event: %w", err)
    }

    log.Printf("[Attacher] DNS Event: %s:%d -> %s:%d | ID: %d | Type: %d | Query: %t",
        ipToStr(dnsData.Base.Saddr), dnsData.Base.Sport,
        ipToStr(dnsData.Base.Daddr), dnsData.Base.Dport,
        dnsData.DnsTransactionId,
        dnsData.DnsQueryType,
        dnsData.IsQuery == 1)

    dnsEvent := convertTCDNSToTypes(dnsData)
    uploader.SendDNSEvent(dnsEvent)

    return nil
}

// convertTCDNSToTypes converts an eBPF TC DNS event struct to the shared types.DNSEvent.
func convertTCDNSToTypes(tcEvent TCDnsEvent) types.DNSEvent {
    // Strip null bytes from the domain name
    queryNameLen := len(tcEvent.DnsQueryName)
    for i, b := range tcEvent.DnsQueryName {
        if b == 0 {
            queryNameLen = i
            break
        }
    }

    queryName := cleanString(string(tcEvent.DnsQueryName[:queryNameLen]))

    return types.DNSEvent{
        Base: types.BaseNetworkEvent{
            SrcAddr:     tcEvent.Base.Saddr,
            DstAddr:     tcEvent.Base.Daddr,
            IPTos:       uint32(tcEvent.Base.IpTos),
            IPTotalLen:  uint32(tcEvent.Base.IpTotalLen),
            IPID:        uint32(tcEvent.Base.IpId),
            IPFragOff:   uint32(tcEvent.Base.IpFragOff),
            IPTtl:       uint32(tcEvent.Base.IpTtl),
            IPProtocol:  uint32(tcEvent.Base.IpProtocol),
            IPCheck:     uint32(tcEvent.Base.IpCheck),
            SrcPort:     uint32(tcEvent.Base.Sport),
            DstPort:     uint32(tcEvent.Base.Dport),
            Seq:         tcEvent.Base.Seq,
            AckSeq:      tcEvent.Base.AckSeq,
            TCPFlags:    uint32(tcEvent.Base.TcpFlags),
            Window:      uint32(tcEvent.Base.Window),
            TCPCheck:    uint32(tcEvent.Base.TcpCheck),
            UDPLen:      uint32(tcEvent.Base.UdpLen),
            UDPCheck:    uint32(tcEvent.Base.UdpCheck),
            TimestampNs: tcEvent.Base.TimestampNs,
            PayloadSize: uint32(tcEvent.Base.PayloadSize),
        },
        TransactionID: uint32(tcEvent.DnsTransactionId),
        QueryType:     uint32(tcEvent.DnsQueryType),
        QueryName:     queryName,
        ResponseCode:  uint32(tcEvent.DnsResponseCode),
        IsQuery:       tcEvent.IsQuery == 1,
    }
}
