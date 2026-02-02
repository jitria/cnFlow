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

// processRedisEvent parses a raw ring buffer sample into a Redis event and forwards it to the manager.
func processRedisEvent(rawData []byte) error {
    var redisData TCRedisEvent

    if err := binary.Read(bytes.NewBuffer(rawData), binary.LittleEndian, &redisData); err != nil {
        return fmt.Errorf("failed to parse Redis event: %w", err)
    }

    // Filter out UNKNOWN commands to avoid false positives
    if redisData.RedisCommandType == 255 {
        return nil
    }

    log.Printf("[Attacher] Redis Event: %s:%d -> %s:%d | Command Type: %d | RESP Type: %d",
        ipToStr(redisData.Base.Saddr), redisData.Base.Sport,
        ipToStr(redisData.Base.Daddr), redisData.Base.Dport,
        redisData.RedisCommandType,
        redisData.RedisRespType)

    redisEvent := convertTCRedisToTypes(redisData)
    uploader.SendRedisEvent(redisEvent)

    return nil
}

// convertTCRedisToTypes converts an eBPF TC Redis event struct to the shared types.RedisEvent.
func convertTCRedisToTypes(tcEvent TCRedisEvent) types.RedisEvent {
    // Use the actual payload length reported by eBPF
    payloadLen := int(tcEvent.Base.PayloadSize)

    // Clamp to buffer size if out of range
    if payloadLen == 0 || payloadLen > len(tcEvent.RedisPayload) {
        payloadLen = len(tcEvent.RedisPayload)
    }

    payload := make([]byte, payloadLen)
    copy(payload, tcEvent.RedisPayload[:payloadLen])

    return types.RedisEvent{
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
            PayloadSize: uint32(payloadLen),
        },
        CommandType: uint32(tcEvent.RedisCommandType),
        RespType:    uint32(tcEvent.RedisRespType),
        Payload:     payload,
    }
}
