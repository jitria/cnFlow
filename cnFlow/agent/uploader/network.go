// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package uploader

import (
    "fmt"
    "log"
    "cnFlow/protobuf"
    "cnFlow/types"
)

// SendHTTPEvent sends an HTTP event to the manager via gRPC stream.
func SendHTTPEvent(httpEvent types.HTTPEvent) {
    if UploaderH.httpStream == nil {
        log.Printf("[UploaderH] HTTP stream not available")
        return
    }

    pbEvent := convertTypesToProtobufHTTP(httpEvent)
    if err := UploaderH.httpStream.Send(pbEvent); err != nil {
        log.Printf("[UploaderH] Failed to send HTTP event: %v", err)
    } else {
        log.Printf("[UploaderH] Sent HTTP event: %s %s -> %s:%d",
            pbEvent.Method, pbEvent.Uri, ipToStr(pbEvent.Base.DstAddr), pbEvent.Base.DstPort)
    }
}

// SendHTTP2Event sends an HTTP/2 event to the manager via gRPC stream.
func SendHTTP2Event(http2Event types.HTTP2Event) {
    if UploaderH.http2Stream == nil {
        log.Printf("[UploaderH] HTTP2 stream not available")
        return
    }

    pbEvent := convertTypesToProtobufHTTP2(http2Event)
    if err := UploaderH.http2Stream.Send(pbEvent); err != nil {
        log.Printf("[UploaderH] Failed to send HTTP2 event: %v", err)
    } else {
        log.Printf("[UploaderH] Sent HTTP2 event: Frame Type %d, Stream %d",
            pbEvent.FrameType, pbEvent.StreamId)
    }
}

// SendDNSEvent sends a DNS event to the manager via gRPC stream.
func SendDNSEvent(dnsEvent types.DNSEvent) {
    if UploaderH.dnsStream == nil {
        log.Printf("[UploaderH] DNS stream not available")
        return
    }

    pbEvent := convertTypesToProtobufDNS(dnsEvent)
    if err := UploaderH.dnsStream.Send(pbEvent); err != nil {
        log.Printf("[UploaderH] Failed to send DNS event: %v", err)
    } else {
        log.Printf("[UploaderH] Sent DNS event: %s (Query: %t)",
            pbEvent.QueryName, pbEvent.IsQuery)
    }
}

// SendRedisEvent sends a Redis event to the manager via gRPC stream.
func SendRedisEvent(redisEvent types.RedisEvent) {
    if UploaderH.redisStream == nil {
        log.Printf("[UploaderH] Redis stream not available")
        return
    }

    pbEvent := convertTypesToProtobufRedis(redisEvent)
    if err := UploaderH.redisStream.Send(pbEvent); err != nil {
        log.Printf("[UploaderH] Failed to send Redis event: %v", err)
    } else {
        log.Printf("[UploaderH] Sent Redis event: Command Type %d", pbEvent.CommandType)
    }
}

// SendICMPEvent sends an ICMP event to the manager via gRPC stream.
func SendICMPEvent(icmpEvent types.ICMPEvent) {
    if UploaderH.icmpStream == nil {
        log.Printf("[UploaderH] ICMP stream not available")
        return
    }

    pbEvent := convertTypesToProtobufICMP(icmpEvent)
    if err := UploaderH.icmpStream.Send(pbEvent); err != nil {
        log.Printf("[UploaderH] Failed to send ICMP event: %v", err)
    } else {
        log.Printf("[UploaderH] Sent ICMP event: Type %d, Code %d",
            pbEvent.Type, pbEvent.Code)
    }
}

// SendKafkaEvent sends a Kafka event to the manager via gRPC stream.
func SendKafkaEvent(kafkaEvent types.KafkaEvent) {
    if UploaderH.kafkaStream == nil {
        log.Printf("[UploaderH] Kafka stream not available")
        return
    }

    pbEvent := convertTypesToProtobufKafka(kafkaEvent)
    if err := UploaderH.kafkaStream.Send(pbEvent); err != nil {
        log.Printf("[UploaderH] Failed to send Kafka event: %v", err)
    } else {
        log.Printf("[UploaderH] Sent Kafka event: API Key %d, Version %d",
            pbEvent.ApiKey, pbEvent.ApiVersion)
    }
}

// convertTypesToProtobufHTTP converts a types.HTTPEvent to its protobuf representation.
func convertTypesToProtobufHTTP(httpEvent types.HTTPEvent) *protobuf.HTTPEvent {
    return &protobuf.HTTPEvent{
        Base:       convertBaseNetworkEvent(httpEvent.Base),
        Method:     httpEvent.Method,
        Uri:        httpEvent.URI,
        StatusCode: httpEvent.StatusCode,
        IsRequest:  httpEvent.IsRequest,
    }
}

// convertTypesToProtobufHTTP2 converts a types.HTTP2Event to its protobuf representation.
func convertTypesToProtobufHTTP2(http2Event types.HTTP2Event) *protobuf.HTTP2Event {
    return &protobuf.HTTP2Event{
        Base:        convertBaseNetworkEvent(http2Event.Base),
        FrameLength: http2Event.FrameLength,
        FrameType:   http2Event.FrameType,
        FrameFlags:  http2Event.FrameFlags,
        StreamId:    http2Event.StreamID,
        Payload:     http2Event.Payload,
    }
}

// convertTypesToProtobufDNS converts a types.DNSEvent to its protobuf representation.
func convertTypesToProtobufDNS(dnsEvent types.DNSEvent) *protobuf.DNSEvent {
    return &protobuf.DNSEvent{
        Base:          convertBaseNetworkEvent(dnsEvent.Base),
        TransactionId: dnsEvent.TransactionID,
        QueryType:     dnsEvent.QueryType,
        QueryName:     dnsEvent.QueryName,
        ResponseCode:  dnsEvent.ResponseCode,
        IsQuery:       dnsEvent.IsQuery,
    }
}

// convertTypesToProtobufRedis converts a types.RedisEvent to its protobuf representation.
func convertTypesToProtobufRedis(redisEvent types.RedisEvent) *protobuf.RedisEvent {
    return &protobuf.RedisEvent{
        Base:        convertBaseNetworkEvent(redisEvent.Base),
        CommandType: redisEvent.CommandType,
        RespType:    redisEvent.RespType,
        Payload:     redisEvent.Payload,
    }
}

// convertTypesToProtobufICMP converts a types.ICMPEvent to its protobuf representation.
func convertTypesToProtobufICMP(icmpEvent types.ICMPEvent) *protobuf.ICMPEvent {
    return &protobuf.ICMPEvent{
        Base:     convertBaseNetworkEvent(icmpEvent.Base),
        Type:     icmpEvent.Type,
        Code:     icmpEvent.Code,
        Id:       icmpEvent.ID,
        Sequence: icmpEvent.Sequence,
    }
}

// convertTypesToProtobufKafka converts a types.KafkaEvent to its protobuf representation.
func convertTypesToProtobufKafka(kafkaEvent types.KafkaEvent) *protobuf.KafkaEvent {
    return &protobuf.KafkaEvent{
        Base:          convertBaseNetworkEvent(kafkaEvent.Base),
        ApiKey:        kafkaEvent.APIKey,
        ApiVersion:    kafkaEvent.APIVersion,
        CorrelationId: kafkaEvent.CorrelationID,
        Payload:       kafkaEvent.Payload,
    }
}

// convertBaseNetworkEvent converts a types.BaseNetworkEvent to its protobuf representation.
func convertBaseNetworkEvent(base types.BaseNetworkEvent) *protobuf.BaseNetworkEvent {
    return &protobuf.BaseNetworkEvent{
        SrcAddr:     base.SrcAddr,
        DstAddr:     base.DstAddr,
        IpTos:       base.IPTos,
        IpTotalLen:  base.IPTotalLen,
        IpId:        base.IPID,
        IpFragOff:   base.IPFragOff,
        IpTtl:       base.IPTtl,
        IpProtocol:  base.IPProtocol,
        IpCheck:     base.IPCheck,
        SrcPort:     base.SrcPort,
        DstPort:     base.DstPort,
        Seq:         base.Seq,
        AckSeq:      base.AckSeq,
        TcpFlags:    base.TCPFlags,
        Window:      base.Window,
        TcpCheck:    base.TCPCheck,
        UdpLen:      base.UDPLen,
        UdpCheck:    base.UDPCheck,
        TimestampNs: base.TimestampNs,
        PayloadSize: base.PayloadSize,
    }
}

// ipToStr converts a uint32 IP address to dotted decimal string.
func ipToStr(ip uint32) string {
    return fmt.Sprintf("%d.%d.%d.%d",
        byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}
