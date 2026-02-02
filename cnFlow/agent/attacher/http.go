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

// processHTTPEvent parses a raw ring buffer sample into an HTTP event and forwards it to the manager.
func processHTTPEvent(rawData []byte) error {
    var httpData TCHttpEvent

    if err := binary.Read(bytes.NewBuffer(rawData), binary.LittleEndian, &httpData); err != nil {
        return fmt.Errorf("failed to parse HTTP event: %w", err)
    }

    log.Printf("[Attacher] HTTP Event: %s:%d -> %s:%d",
        ipToStr(httpData.Base.Saddr), httpData.Base.Sport,
        ipToStr(httpData.Base.Daddr), httpData.Base.Dport)

    httpEvent := convertTCHTTPToTypes(httpData)
    uploader.SendHTTPEvent(httpEvent)

    return nil
}

// convertTCHTTPToTypes converts an eBPF TC HTTP event struct to the shared types.HTTPEvent.
func convertTCHTTPToTypes(tcEvent TCHttpEvent) types.HTTPEvent {
    return types.HTTPEvent{
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
        Method:     cleanString(string(tcEvent.HttpMethod[:])),
        URI:        cleanString(string(tcEvent.HttpUri[:])),
        StatusCode: cleanString(string(tcEvent.HttpStatusCode[:])),
        IsRequest:  tcEvent.IsRequest == 1,
    }
}
