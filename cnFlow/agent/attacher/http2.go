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

// processHTTP2Event parses a raw ring buffer sample into an HTTP/2 event and forwards it to the manager.
func processHTTP2Event(rawData []byte) error {
    var http2Data TCHttp2Event

    if err := binary.Read(bytes.NewBuffer(rawData), binary.LittleEndian, &http2Data); err != nil {
        return fmt.Errorf("failed to parse HTTP/2 event: %w", err)
    }

    log.Printf("[Attacher] HTTP/2 Event: %s:%d -> %s:%d | Frame Type: %d | Stream: %d",
        ipToStr(http2Data.Base.Saddr), http2Data.Base.Sport,
        ipToStr(http2Data.Base.Daddr), http2Data.Base.Dport,
        http2Data.Http2FrameType, http2Data.Http2StreamId)

    http2Event := convertTCHTTP2ToTypes(http2Data)
    uploader.SendHTTP2Event(http2Event)

    return nil
}

// convertTCHTTP2ToTypes converts an eBPF TC HTTP/2 event struct to the shared types.HTTP2Event.
func convertTCHTTP2ToTypes(tcEvent TCHttp2Event) types.HTTP2Event {
    frameLength := int(tcEvent.Http2FrameLength)

    var payload []byte
    if frameLength > 0 && frameLength <= len(tcEvent.Payload) {
        payload = make([]byte, frameLength)
        copy(payload, tcEvent.Payload[:frameLength])
    } else {
        payload = []byte{}
    }

    return types.HTTP2Event{
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
        FrameLength: tcEvent.Http2FrameLength,
        FrameType:   uint32(tcEvent.Http2FrameType),
        FrameFlags:  uint32(tcEvent.Http2FrameFlags),
        StreamID:    tcEvent.Http2StreamId,
        Payload:     payload,
    }
}
