// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package protocol

import (
	"encoding/binary"
	"fmt"

	"cnFlow/protobuf"
)

const (
	MAX_KAFKA_TOPIC_LENGTH = 16
)

// KafkaAnalysisResult contains all information extracted from a Kafka event.
type KafkaAnalysisResult struct {
	// Common network information
	BaseInfo *BaseNetworkInfo `json:"base_info"`

	// Kafka header
	ApiKey        uint32 `json:"api_key"`
	ApiKeyName    string `json:"api_key_name"`
	ApiVersion    uint32 `json:"api_version"`
	CorrelationID uint32 `json:"correlation_id"`
	PayloadSize   int    `json:"payload_size"`

	// Message type (request / response)
	IsRequest bool `json:"is_request"`

	// Extracted topic (if present)
	Topic string `json:"topic,omitempty"`
}

// AnalyzeKafkaEventDetailed parses a Kafka event and returns KafkaAnalysisResult.
func AnalyzeKafkaEventDetailed(event *protobuf.KafkaEvent) *KafkaAnalysisResult {
	res := &KafkaAnalysisResult{
		BaseInfo:      ParseBaseNetworkInfo(event.Base),
		ApiKey:        event.ApiKey,
		ApiKeyName:    getKafkaAPIName(event.ApiKey),
		ApiVersion:    event.ApiVersion,
		CorrelationID: event.CorrelationId,
		PayloadSize:   len(event.Payload),
	}

	// Distinguish request/response (Kafka API key 0-67: request, others: response)
	if event.ApiKey > 0 && event.ApiKey <= 67 {
		res.IsRequest = true
		if topic, ok := extractTopic(event.Payload); ok {
			res.Topic = topic
		}
	}

	return res
}

// extractTopic attempts to extract a Kafka topic name from the payload.
func extractTopic(payload []byte) (string, bool) {
	if len(payload) == 0 {
		return "", false
	}
	if topic, ok := scanTopic(payload); ok {
		clean := cleanTopicName(topic)
		if isValidTopicName(clean) {
			return clean, true
		}
	}
	return "", false
}

// scanTopic scans the payload for a topic name using the compact string encoding.
func scanTopic(payload []byte) (string, bool) {
	for i := 0; i < len(payload)-3; i++ {
		if payload[i] == 0x02 {
			topicLen := int(payload[i+1])
			// Normal length
			if topicLen >= 3 && topicLen <= MAX_KAFKA_TOPIC_LENGTH && i+2+topicLen <= len(payload) {
				candidate := payload[i+2 : i+2+topicLen]
				if validTopic(candidate) {
					return string(candidate), true
				}
			}
			// Some implementations send length as +1
			if topicLen > 3 && topicLen <= MAX_KAFKA_TOPIC_LENGTH+1 && i+2+topicLen-1 <= len(payload) {
				candidate := payload[i+2 : i+2+topicLen-1]
				if validTopic(candidate) {
					return string(candidate), true
				}
			}
		}
	}
	return "", false
}

// cleanTopicName removes trailing invalid characters from a topic name.
func cleanTopicName(topic string) string {
	if topic == "" {
		return topic
	}
	invalid := []rune{
		']', ',', '#', '&', '"', '\'',
		':', '/', '\\', '*', '?', '<', '>', '|', '!',
		'@', '$', '%', '^', '(', ')', '+', '=', '[', '{', '}', ';',
		' ', '\t', '\n', '\r',
	}
	clean := []rune(topic)
	for len(clean) > 0 {
		last := clean[len(clean)-1]
		for _, inv := range invalid {
			if last == inv {
				clean = clean[:len(clean)-1]
				goto continueOuter
			}
		}
		break
	continueOuter:
	}
	return string(clean)
}

// validTopic checks whether raw bytes contain only printable ASCII characters.
func validTopic(raw []byte) bool {
	if len(raw) == 0 || len(raw) > MAX_KAFKA_TOPIC_LENGTH {
		return false
	}
	for _, b := range raw {
		if b < 0x20 || b > 0x7E {
			return false
		}
	}
	return true
}

// isValidTopicName checks whether a topic name contains only valid Kafka topic characters.
func isValidTopicName(topic string) bool {
	if topic == "" || len(topic) > MAX_KAFKA_TOPIC_LENGTH {
		return false
	}
	for _, r := range topic {
		if !(r == '-' || r == '_' || r == '.' ||
			(r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// summarizeKafkaHeader extracts the Kafka message header fields from raw payload bytes.
func summarizeKafkaHeader(payload []byte) (size uint32, apiKey uint16, apiVer uint16, corrID uint32, ok bool) {
	if len(payload) < 14 {
		return
	}
	size = binary.BigEndian.Uint32(payload[0:4])
	apiKey = binary.BigEndian.Uint16(payload[4:6])
	apiVer = binary.BigEndian.Uint16(payload[6:8])
	corrID = binary.BigEndian.Uint32(payload[8:12])
	ok = true
	return
}

// getKafkaAPIName returns the human-readable name for a Kafka API key.
func getKafkaAPIName(apiKey uint32) string {
	switch apiKey {
	case 0:
		return "Produce"
	case 1:
		return "Fetch"
	case 2:
		return "ListOffsets"
	case 3:
		return "Metadata"
	case 4:
		return "LeaderAndIsr"
	case 5:
		return "StopReplica"
	case 6:
		return "UpdateMetadata"
	case 7:
		return "ControlledShutdown"
	case 8:
		return "OffsetCommit"
	case 9:
		return "OffsetFetch"
	case 10:
		return "FindCoordinator"
	case 11:
		return "JoinGroup"
	case 12:
		return "Heartbeat"
	case 13:
		return "LeaveGroup"
	case 14:
		return "SyncGroup"
	case 15:
		return "DescribeGroups"
	case 16:
		return "ListGroups"
	case 17:
		return "SaslHandshake"
	case 18:
		return "ApiVersions"
	case 19:
		return "CreateTopics"
	case 20:
		return "DeleteTopics"
	case 21:
		return "DeleteRecords"
	case 22:
		return "InitProducerId"
	case 23:
		return "OffsetForLeaderEpoch"
	case 24:
		return "AddPartitionsToTxn"
	case 25:
		return "AddOffsetsToTxn"
	case 26:
		return "EndTxn"
	case 27:
		return "WriteTxnMarkers"
	case 28:
		return "TxnOffsetCommit"
	case 29:
		return "DescribeAcls"
	case 30:
		return "CreateAcls"
	case 31:
		return "DeleteAcls"
	case 32:
		return "DescribeConfigs"
	case 33:
		return "AlterConfigs"
	default:
		return fmt.Sprintf("Unknown_%d", apiKey)
	}
}
