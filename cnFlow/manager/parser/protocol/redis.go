// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package protocol

import (
    "fmt"
    "strings"

    "cnFlow/protobuf"
)

// RedisAnalysisResult contains all analysis results from a Redis event.
type RedisAnalysisResult struct {
    // Basic network information
    BaseInfo *BaseNetworkInfo `json:"base_info"`

    // Redis protocol information
    CommandType     uint32 `json:"command_type"`
    CommandName     string `json:"command_name"`
    RespType        uint32 `json:"resp_type"`
    RespTypeName    string `json:"resp_type_name"`
    PayloadSize     int    `json:"payload_size"`
    CleanedPayload  string `json:"cleaned_payload"`

    // Request/response distinction
    IsRequest       bool `json:"is_request"`
    IsResponse      bool `json:"is_response"`

    // Detailed analysis by command
    CommandAnalysis *RedisCommandAnalysis `json:"command_analysis,omitempty"`

    // Detailed analysis by response
    ResponseAnalysis *RedisResponseAnalysis `json:"response_analysis,omitempty"`

    // Key/value information
    KeyValueInfo *RedisKeyValueInfo `json:"key_value_info,omitempty"`
}

type RedisCommandAnalysis struct {
    Purpose     string `json:"purpose"`
    Operation   string `json:"operation"`
    Context     string `json:"context,omitempty"`
    Direction   string `json:"direction"`
    ExpectedResponse string `json:"expected_response,omitempty"`
}

type RedisResponseAnalysis struct {
    Type        string `json:"type"`
    Result      string `json:"result,omitempty"`
    Content     string `json:"content,omitempty"`
    Cause       string `json:"cause,omitempty"`
    Meaning     string `json:"meaning,omitempty"`
    Size        int    `json:"size,omitempty"`
    Elements    int    `json:"elements,omitempty"`
}

type RedisKeyValueInfo struct {
    Key         string   `json:"key,omitempty"`
    Value       string   `json:"value,omitempty"`
    Hash        string   `json:"hash,omitempty"`
    Field       string   `json:"field,omitempty"`
    Set         string   `json:"set,omitempty"`
    Member      string   `json:"member,omitempty"`
    Score       string   `json:"score,omitempty"`
    StartIndex  string   `json:"start_index,omitempty"`
    StopIndex   string   `json:"stop_index,omitempty"`
    ExtractedValues []string `json:"extracted_values,omitempty"`
}

// AnalyzeRedisEventDetailed analyzes a Redis event and returns all results.
func AnalyzeRedisEventDetailed(event *protobuf.RedisEvent) *RedisAnalysisResult {
    cleanedPayload := cleanString(string(event.Payload))

    result := &RedisAnalysisResult{
        // Basic network information
        BaseInfo: ParseBaseNetworkInfo(event.Base),

        // Redis protocol information
        CommandType:    event.CommandType,
        CommandName:    GetRedisCommandName(event.CommandType),
        RespType:       event.RespType,
        RespTypeName:   GetRedisRespTypeName(event.RespType),
        PayloadSize:    len(event.Payload),
        CleanedPayload: cleanedPayload,

        // Request/response distinction
        IsRequest:  event.CommandType != 254,
        IsResponse: event.CommandType == 254,
    }

    // Extract key/value information
    result.KeyValueInfo = extractRedisKeyValueInfo(cleanedPayload, event.CommandType)

    // Detailed analysis by request/response
    if result.IsResponse {
        result.ResponseAnalysis = analyzeRedisResponse(event, cleanedPayload)
    } else {
        result.CommandAnalysis = analyzeRedisCommand(event, cleanedPayload)
    }

    return result
}

// ProcessRedisEventDetailed is kept for backward compatibility (no log output).
func ProcessRedisEventDetailed(event *protobuf.RedisEvent) {
    // This function no longer outputs logs
    // Use AnalyzeRedisEventDetailed if needed
}

// analyzeRedisCommand analyzes a Redis command and determines its purpose and operation type.
func analyzeRedisCommand(event *protobuf.RedisEvent, payload string) *RedisCommandAnalysis {
    analysis := &RedisCommandAnalysis{
        Direction: fmt.Sprintf("%s:%d -> %s:%d", 
            IpToStr(event.Base.SrcAddr), event.Base.SrcPort,
            IpToStr(event.Base.DstAddr), event.Base.DstPort),
    }
    
    switch event.CommandType {
    case 1: // GET
        analysis.Purpose = "Retrieve value by key"
        analysis.Operation = "Read operation"
    case 2: // SET
        analysis.Purpose = "Store key-value pair"
        analysis.Operation = "Write operation"
    case 3: // PING
        analysis.Purpose = "Test connection liveness"
        analysis.Operation = "Health check"
        analysis.ExpectedResponse = "PONG"
    case 4: // HGET
        analysis.Purpose = "Get hash field value"
        analysis.Operation = "Hash read operation"
    case 5: // HSET
        analysis.Purpose = "Set hash field value"
        analysis.Operation = "Hash write operation"
    case 6: // SADD
        analysis.Purpose = "Add member to set"
        analysis.Operation = "Set write operation"
    case 7: // ZADD
        analysis.Purpose = "Add member to sorted set"
        analysis.Operation = "Sorted set write operation"
    case 8: // INFO
        analysis.Purpose = "Get server information"
        analysis.Operation = "Administrative operation"
        analysis.Context = "Server monitoring"
    case 9: // ZRANGE
        analysis.Purpose = "Get sorted set range"
        analysis.Operation = "Sorted set read operation"
    default:
        analysis.Purpose = "Unrecognized or custom command"
        analysis.Operation = "Unknown operation"
    }
    
    return analysis
}

// analyzeRedisResponse analyzes a Redis response based on its RESP type.
func analyzeRedisResponse(event *protobuf.RedisEvent, payload string) *RedisResponseAnalysis {
    analysis := &RedisResponseAnalysis{
        Size: len(payload),
    }
    
    switch event.RespType {
    case 43: // '+' (Simple String)
        analysis.Type = "Success confirmation"
        if strings.Contains(payload, "OK") {
            analysis.Result = "Command executed successfully"
        } else if strings.Contains(payload, "PONG") {
            analysis.Result = "PING response received"
        } else {
            analysis.Content = TruncateString(payload, 50)
        }
    case 45: // '-' (Error)
        analysis.Type = "Command execution error"
        analysis.Content = TruncateString(payload, 100)
        if strings.Contains(payload, "WRONGTYPE") {
            analysis.Cause = "Operation against wrong data type"
        } else if strings.Contains(payload, "NOAUTH") {
            analysis.Cause = "Authentication required"
        } else if strings.Contains(payload, "ERR") {
            analysis.Cause = "General command error"
        }
    case 58: // ':' (Integer)
        analysis.Type = "Numeric result"
        analysis.Content = TruncateString(payload, 20)
        if payload == "1" {
            analysis.Meaning = "Success or item added"
        } else if payload == "0" {
            analysis.Meaning = "Failure or item already exists"
        }
    case 36: // '$' (Bulk String)
        analysis.Type = "String data response"
        if strings.Contains(payload, "redis_version") {
            analysis.Content = "Server information (INFO response)"
        } else {
            analysis.Content = TruncateString(payload, 100)
        }
    case 42: // '*' (Array)
        analysis.Type = "Multiple values response"
        analysis.Content = TruncateString(payload, 100)
        // Estimate number of array elements
        elements := strings.Count(payload, "\r\n")
        if elements > 0 {
            analysis.Elements = elements / 2 // Approximate estimate based on RESP protocol characteristics
        }
    default:
        analysis.Type = "Unknown response type"
        analysis.Content = TruncateString(payload, 100)
    }
    
    return analysis
}

// extractRedisKeyValueInfo extracts key, value, and specialized fields from a Redis payload.
func extractRedisKeyValueInfo(payload string, commandType uint32) *RedisKeyValueInfo {
    info := &RedisKeyValueInfo{}

    // Extract basic key
    key := extractRedisKey(payload)
    if key != "" {
        info.Key = key
    }

    // Extract key-value pairs
    keyValues := extractRedisKeyValue(payload)
    info.ExtractedValues = keyValues

    // Extract specialized information by command type
    switch commandType {
    case 2: // SET
        if len(keyValues) >= 2 {
            info.Key = keyValues[0]
            info.Value = TruncateString(keyValues[1], 50)
        }
    case 4, 5: // HGET, HSET
        if len(keyValues) >= 2 {
            info.Hash = keyValues[0]
            info.Field = keyValues[1]
            if len(keyValues) >= 3 {
                info.Value = TruncateString(keyValues[2], 50)
            }
        }
    case 6: // SADD
        if len(keyValues) >= 2 {
            info.Set = keyValues[0]
            info.Member = keyValues[1]
        }
    case 7: // ZADD
        if len(keyValues) >= 3 {
            info.Set = keyValues[0]
            info.Score = keyValues[1]
            info.Member = keyValues[2]
        }
    case 9: // ZRANGE
        if len(keyValues) >= 3 {
            info.Set = keyValues[0]
            info.StartIndex = keyValues[1]
            info.StopIndex = keyValues[2]
        }
    }
    
    return info
}

// extractRedisKey extracts the primary key from a Redis command payload.
func extractRedisKey(payload string) string {
    lines := strings.Split(payload, "\r\n")
    for i, line := range lines {
        if strings.HasPrefix(line, "*") && i+2 < len(lines) {
            if strings.HasPrefix(lines[i+2], "$") && i+3 < len(lines) {
                return lines[i+3]
            }
        }
    }
    
    parts := strings.Fields(payload)
    if len(parts) >= 2 {
        return parts[1]
    }
    
    return ""
}

// extractRedisKeyValue extracts key-value arguments from a Redis RESP payload.
func extractRedisKeyValue(payload string) []string {
    lines := strings.Split(payload, "\r\n")
    var result []string
    
    for i, line := range lines {
        if strings.HasPrefix(line, "*") {
            j := i + 1
            for j < len(lines) && len(result) < 3 {
                if strings.HasPrefix(lines[j], "$") && j+1 < len(lines) {
                    result = append(result, lines[j+1])
                    j += 2
                } else {
                    j++
                }
            }
            break
        }
    }
    
    if len(result) == 0 {
        parts := strings.Fields(payload)
        if len(parts) >= 3 {
            result = append(result, parts[1], parts[2])
            if len(parts) >= 4 {
                result = append(result, parts[3])
            }
        }
    }
    
    return result
}

// cleanString removes control characters and trims whitespace from a string.
func cleanString(s string) string {
    // Remove control characters
    result := strings.Map(func(r rune) rune {
        if r < 32 && r != '\n' && r != '\r' && r != '\t' {
            return -1
        }
        return r
    }, s)

    return strings.TrimSpace(result)
}

// GetRedisCommandName returns the name of a Redis command type.
func GetRedisCommandName(commandType uint32) string {
    switch commandType {
    case 1: return "GET"
    case 2: return "SET"
    case 3: return "PING"
    case 4: return "HGET"
    case 5: return "HSET"
    case 6: return "SADD"
    case 7: return "ZADD"
    case 8: return "INFO"
    case 9: return "ZRANGE"
    case 254: return "REPLY"
    case 255: return "UNKNOWN"
    default: return fmt.Sprintf("CMD_%d", commandType)
    }
}

// GetRedisRespTypeName returns the name of a Redis RESP type.
func GetRedisRespTypeName(respType uint32) string {
    switch respType {
    case 43: return "Simple String (+)"
    case 45: return "Error (-)"
    case 58: return "Integer (:)"
    case 36: return "Bulk String ($)"
    case 42: return "Array (*)"
    default: return fmt.Sprintf("Unknown(%d)", respType)
    }
}
