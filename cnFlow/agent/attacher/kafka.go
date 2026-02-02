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

const MAX_KAFKA_TOPIC_LENGTH = 16

// processKafkaEvent parses a raw ring buffer sample into a Kafka event and forwards it to the manager.
func processKafkaEvent(rawData []byte) error {
    var kafkaData TCKafkaEvent

    if err := binary.Read(bytes.NewBuffer(rawData), binary.LittleEndian, &kafkaData); err != nil {
        return fmt.Errorf("failed to parse Kafka event: %w", err)
    }

    log.Printf("[Attacher] Kafka Event: %s:%d -> %s:%d | API Key: %d | Version: %d | CorrelationID: %d",
        ipToStr(kafkaData.Base.Saddr), kafkaData.Base.Sport,
        ipToStr(kafkaData.Base.Daddr), kafkaData.Base.Dport,
        kafkaData.KafkaApiKey,
        kafkaData.KafkaApiVersion,
        kafkaData.KafkaCorrelationId)

    kafkaEvent := convertTCKafkaToTypes(kafkaData)
    uploader.SendKafkaEvent(kafkaEvent)

    return nil
}

// convertTCKafkaToTypes converts an eBPF TC Kafka event struct to the shared types.KafkaEvent.
func convertTCKafkaToTypes(tcEvent TCKafkaEvent) types.KafkaEvent {
    var payload []byte

    actualPayloadSize := int(tcEvent.Base.PayloadSize)
    maxPayloadSize := len(tcEvent.Payload)

    payloadSize := maxPayloadSize
    if actualPayloadSize > 0 && actualPayloadSize < maxPayloadSize {
        payloadSize = actualPayloadSize
    }

    if payloadSize > 0 {
        payload = make([]byte, payloadSize)
        copy(payload, tcEvent.Payload[:payloadSize])
    } else {
        payload = []byte{}
    }

    return types.KafkaEvent{
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
        APIKey:        uint32(tcEvent.KafkaApiKey),
        APIVersion:    uint32(tcEvent.KafkaApiVersion),
        CorrelationID: tcEvent.KafkaCorrelationId,
        Payload:       payload,
    }
}
