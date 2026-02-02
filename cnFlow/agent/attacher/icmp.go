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

// processICMPEvent parses a raw ring buffer sample into an ICMP event and forwards it to the manager.
func processICMPEvent(rawData []byte) error {
    var icmpData TCIcmpEvent

    if err := binary.Read(bytes.NewBuffer(rawData), binary.LittleEndian, &icmpData); err != nil {
        return fmt.Errorf("failed to parse ICMP event: %w", err)
    }

    log.Printf("[Attacher] ICMP Event: %s -> %s | Type: %d | Code: %d | ID: %d | Seq: %d",
        ipToStr(icmpData.Base.Saddr),
        ipToStr(icmpData.Base.Daddr),
        icmpData.IcmpType,
        icmpData.IcmpCode,
        icmpData.IcmpId,
        icmpData.IcmpSeq)

    icmpEvent := convertTCICMPToTypes(icmpData)
    uploader.SendICMPEvent(icmpEvent)

    return nil
}

// convertTCICMPToTypes converts an eBPF TC ICMP event struct to the shared types.ICMPEvent.
func convertTCICMPToTypes(tcEvent TCIcmpEvent) types.ICMPEvent {
    return types.ICMPEvent{
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
        Type:     uint32(tcEvent.IcmpType),
        Code:     uint32(tcEvent.IcmpCode),
        ID:       uint32(tcEvent.IcmpId),
        Sequence: uint32(tcEvent.IcmpSeq),
    }
}
