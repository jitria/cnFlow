// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package protocol

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "strings"
    "sync"

    "cnFlow/protobuf"
    "golang.org/x/net/http2/hpack"
)

// ConnectionHpackDecoder manages HPACK decoders per connection
type ConnectionHpackDecoder struct {
    decoders map[string]*hpack.Decoder
    mu       sync.RWMutex
}

var globalHpackDecoder *ConnectionHpackDecoder

// init initializes the global HPACK decoder.
func init() {
    globalHpackDecoder = NewConnectionHpackDecoder()
}

// NewConnectionHpackDecoder creates a new connection-scoped HPACK decoder manager.
func NewConnectionHpackDecoder() *ConnectionHpackDecoder {
    return &ConnectionHpackDecoder{
        decoders: make(map[string]*hpack.Decoder),
    }
}

// getDecoder returns or creates an HPACK decoder for the given connection key.
func (c *ConnectionHpackDecoder) getDecoder(connKey string) *hpack.Decoder {
    c.mu.RLock()
    decoder, exists := c.decoders[connKey]
    c.mu.RUnlock()
    
    if !exists {
        c.mu.Lock()
        decoder, exists = c.decoders[connKey]
        if !exists {
            decoder = hpack.NewDecoder(4096, nil)
            c.decoders[connKey] = decoder
        }
        c.mu.Unlock()
    }
    
    return decoder
}

// DecodeHeaders decodes HPACK-encoded headers for the given connection.
func (c *ConnectionHpackDecoder) DecodeHeaders(connKey string, data []byte) (map[string]string, error) {
    decoder := c.getDecoder(connKey)
    
    headers := make(map[string]string)
    headerFunc := func(f hpack.HeaderField) {
        headers[f.Name] = f.Value
    }
    
    decoder.SetEmitFunc(headerFunc)
    _, err := decoder.Write(data)
    if err != nil {
        return nil, fmt.Errorf("failed to decode HPACK headers: %w", err)
    }
    
    return headers, nil
}

// HTTP2AnalysisResult contains all analysis results from an HTTP/2 event.
type HTTP2AnalysisResult struct {
    // Basic network information
    BaseInfo *BaseNetworkInfo `json:"base_info"`

    // HTTP/2 protocol information
    FrameLength uint32 `json:"frame_length"`
    FrameType   uint32 `json:"frame_type"`
    FrameTypeName string `json:"frame_type_name"`
    FrameFlags  uint32 `json:"frame_flags"`
    StreamID    uint32 `json:"stream_id"`
    PayloadSize int    `json:"payload_size"`

    // Detailed analysis by frame type
    FrameAnalysis *HTTP2FrameAnalysis `json:"frame_analysis"`

    // HPACK header analysis (for HEADERS/CONTINUATION frames)
    HeadersAnalysis *HTTP2HeadersAnalysis `json:"headers_analysis,omitempty"`

    // Data payload analysis (for DATA frames)
    DataAnalysis *HTTP2DataAnalysis `json:"data_analysis,omitempty"`

    // SETTINGS frame analysis (for SETTINGS frames)
    SettingsAnalysis *HTTP2SettingsAnalysis `json:"settings_analysis,omitempty"`
}

type HTTP2FrameAnalysis struct {
    FrameType   string   `json:"frame_type"`
    Purpose     string   `json:"purpose"`
    Direction   string   `json:"direction"`
    StreamID    uint32   `json:"stream_id"`
    Flags       []string `json:"flags,omitempty"`
    IsEndStream bool     `json:"is_end_stream"`
    IsEndHeaders bool    `json:"is_end_headers"`
}

type HTTP2HeadersAnalysis struct {
    DecodedHeaders map[string]string `json:"decoded_headers"`
    IsRequest      bool              `json:"is_request"`
    IsResponse     bool              `json:"is_response"`

    // Request information
    Method    string `json:"method,omitempty"`
    Path      string `json:"path,omitempty"`
    Authority string `json:"authority,omitempty"`
    Scheme    string `json:"scheme,omitempty"`

    // Response information
    Status string `json:"status,omitempty"`

    // Important headers
    ContentType   string `json:"content_type,omitempty"`
    ContentLength string `json:"content_length,omitempty"`
    UserAgent     string `json:"user_agent,omitempty"`

    // Path analysis
    PathAnalysis *HTTP2PathAnalysis `json:"path_analysis,omitempty"`
}

type HTTP2PathAnalysis struct {
    Path            string            `json:"path"`
    QueryParameters map[string]string `json:"query_parameters,omitempty"`
    ParameterCount  int               `json:"parameter_count"`
    PathDepth       int               `json:"path_depth"`
}

type HTTP2DataAnalysis struct {
    Size        int    `json:"size"`
    DataType    string `json:"data_type"`
    Content     string `json:"content,omitempty"`
    IsEndStream bool   `json:"is_end_stream"`
}

type HTTP2SettingsAnalysis struct {
    IsAck        bool                    `json:"is_ack"`
    SettingsCount int                    `json:"settings_count"`
    Settings     map[string]uint32       `json:"settings,omitempty"`
}

// AnalyzeHTTP2EventDetailed analyzes an HTTP/2 event and returns all results.
func AnalyzeHTTP2EventDetailed(event *protobuf.HTTP2Event) *HTTP2AnalysisResult {
    connKey := fmt.Sprintf("%s:%d-%s:%d",
        IpToStr(event.Base.SrcAddr), event.Base.SrcPort,
        IpToStr(event.Base.DstAddr), event.Base.DstPort)

    result := &HTTP2AnalysisResult{
        // Basic network information
        BaseInfo: ParseBaseNetworkInfo(event.Base),

        // HTTP/2 protocol information
        FrameLength:   event.FrameLength,
        FrameType:     event.FrameType,
        FrameTypeName: GetHTTP2FrameTypeName(event.FrameType),
        FrameFlags:    event.FrameFlags,
        StreamID:      event.StreamId,
        PayloadSize:   len(event.Payload),

        // Detailed analysis by frame type
        FrameAnalysis: analyzeHTTP2Frame(event),
    }

    // Specialized analysis by frame type
    switch event.FrameType {
    case 1, 9: // HEADERS, CONTINUATION
        if analysis := analyzeHTTP2Headers(event, connKey); analysis != nil {
            result.HeadersAnalysis = analysis
        }
    case 0: // DATA
        result.DataAnalysis = analyzeHTTP2Data(event)
    case 4: // SETTINGS
        result.SettingsAnalysis = analyzeHTTP2Settings(event)
    }

    return result
}

// ProcessHTTP2EventDetailed is kept for backward compatibility (no log output).
func ProcessHTTP2EventDetailed(event *protobuf.HTTP2Event) {
    // This function no longer outputs logs
    // Use AnalyzeHTTP2EventDetailed if needed
}

// analyzeHTTP2Frame analyzes an HTTP/2 frame and determines its purpose and flags.
func analyzeHTTP2Frame(event *protobuf.HTTP2Event) *HTTP2FrameAnalysis {
    analysis := &HTTP2FrameAnalysis{
        FrameType: GetHTTP2FrameTypeName(event.FrameType),
        Direction: fmt.Sprintf("%s:%d -> %s:%d", 
            IpToStr(event.Base.SrcAddr), event.Base.SrcPort,
            IpToStr(event.Base.DstAddr), event.Base.DstPort),
        StreamID: event.StreamId,
    }

    // Analyze flags
    var flags []string
    if event.FrameFlags&0x01 != 0 {
        flags = append(flags, "END_STREAM")
        analysis.IsEndStream = true
    }
    if event.FrameFlags&0x04 != 0 {
        flags = append(flags, "END_HEADERS")
        analysis.IsEndHeaders = true
    }
    if event.FrameFlags&0x08 != 0 {
        flags = append(flags, "PADDED")
    }
    if event.FrameFlags&0x20 != 0 {
        flags = append(flags, "PRIORITY")
    }
    analysis.Flags = flags

    // Purpose by frame type
    switch event.FrameType {
    case 0: // DATA
        analysis.Purpose = "Convey arbitrary, variable-length sequences of octets"
    case 1: // HEADERS
        analysis.Purpose = "Open a stream and carry HTTP header fields"
    case 2: // PRIORITY
        analysis.Purpose = "Specify sender-advised priority of a stream"
    case 3: // RST_STREAM
        analysis.Purpose = "Terminate a stream immediately"
    case 4: // SETTINGS
        analysis.Purpose = "Convey configuration parameters for connection"
    case 5: // PUSH_PROMISE
        analysis.Purpose = "Notify peer of server push intention"
    case 6: // PING
        analysis.Purpose = "Test connection liveness and round-trip time"
    case 7: // GOAWAY
        analysis.Purpose = "Initiate shutdown of connection"
    case 8: // WINDOW_UPDATE
        analysis.Purpose = "Implement flow control"
    case 9: // CONTINUATION
        analysis.Purpose = "Continue sequence of header block fragments"
    default:
        analysis.Purpose = "Unknown frame type"
    }
    
    return analysis
}

// analyzeHTTP2Headers decodes and analyzes HTTP/2 HEADERS frame payload.
func analyzeHTTP2Headers(event *protobuf.HTTP2Event, connKey string) *HTTP2HeadersAnalysis {
    cleanPayload := bytes.Trim(event.Payload, "\x00")
    if len(cleanPayload) == 0 {
        return nil
    }
    
    headers, err := globalHpackDecoder.DecodeHeaders(connKey, cleanPayload)
    if err != nil {
        return &HTTP2HeadersAnalysis{
            DecodedHeaders: map[string]string{"decode_error": err.Error()},
        }
    }
    
    analysis := &HTTP2HeadersAnalysis{
        DecodedHeaders: headers,
    }

    // Distinguish request/response and extract information
    for name, value := range headers {
        switch name {
        case ":method":
            analysis.Method = value
            analysis.IsRequest = true
        case ":path":
            analysis.Path = value
            analysis.PathAnalysis = analyzeHTTP2Path(value)
        case ":authority":
            analysis.Authority = value
        case ":status":
            analysis.Status = value
            analysis.IsResponse = true
        case ":scheme":
            analysis.Scheme = value
        case "content-type":
            analysis.ContentType = value
        case "content-length":
            analysis.ContentLength = value
        case "user-agent":
            analysis.UserAgent = value
        }
    }
    
    return analysis
}

// analyzeHTTP2Path analyzes an HTTP/2 request path and its query parameters.
func analyzeHTTP2Path(path string) *HTTP2PathAnalysis {
    analysis := &HTTP2PathAnalysis{
        Path:      path,
        PathDepth: strings.Count(path, "/"),
    }

    // Analyze query parameters
    if strings.Contains(path, "?") {
        parts := strings.Split(path, "?")
        if len(parts) > 1 {
            queryParams := make(map[string]string)
            params := strings.Split(parts[1], "&")
            analysis.ParameterCount = len(params)
            
            for _, param := range params {
                if strings.Contains(param, "=") {
                    kv := strings.SplitN(param, "=", 2)
                    queryParams[kv[0]] = kv[1]
                } else {
                    queryParams[param] = ""
                }
            }
            analysis.QueryParameters = queryParams
        }
    }
    
    return analysis
}

// analyzeHTTP2Data analyzes an HTTP/2 DATA frame payload.
func analyzeHTTP2Data(event *protobuf.HTTP2Event) *HTTP2DataAnalysis {
    cleanPayload := bytes.Trim(event.Payload, "\x00")
    
    analysis := &HTTP2DataAnalysis{
        Size:        len(cleanPayload),
        IsEndStream: event.FrameFlags&0x01 != 0,
    }
    
    if len(cleanPayload) > 0 {
        payloadStr := string(cleanPayload)

        // Detect data type
        if strings.HasPrefix(strings.TrimSpace(payloadStr), "{") {
            analysis.DataType = "JSON"
        } else if strings.HasPrefix(strings.TrimSpace(payloadStr), "<") {
            analysis.DataType = "XML/HTML"
        } else {
            analysis.DataType = "Plain text or binary"
        }

        // Content preview
        if len(payloadStr) > 100 {
            analysis.Content = payloadStr[:100] + "..."
        } else {
            analysis.Content = payloadStr
        }
    }
    
    return analysis
}

// analyzeHTTP2Settings parses an HTTP/2 SETTINGS frame.
func analyzeHTTP2Settings(event *protobuf.HTTP2Event) *HTTP2SettingsAnalysis {
    analysis := &HTTP2SettingsAnalysis{
        IsAck: event.FrameFlags&0x01 != 0,
    }
    
    if !analysis.IsAck && len(event.Payload) >= 6 && event.FrameLength%6 == 0 {
        settingsCount := int(event.FrameLength / 6)
        analysis.SettingsCount = settingsCount
        analysis.Settings = make(map[string]uint32)
        
        for i := 0; i < settingsCount; i++ {
            offset := i * 6
            if offset+6 <= len(event.Payload) {
                settingID := binary.BigEndian.Uint16(event.Payload[offset : offset+2])
                settingValue := binary.BigEndian.Uint32(event.Payload[offset+2 : offset+6])
                
                settingName := GetHTTP2SettingName(settingID)
                analysis.Settings[settingName] = settingValue
            }
        }
    }
    
    return analysis
}

// GetHTTP2FrameTypeName returns the name of an HTTP/2 frame type.
func GetHTTP2FrameTypeName(frameType uint32) string {
    switch frameType {
    case 0: return "DATA"
    case 1: return "HEADERS"
    case 2: return "PRIORITY"
    case 3: return "RST_STREAM"
    case 4: return "SETTINGS"
    case 5: return "PUSH_PROMISE"
    case 6: return "PING"
    case 7: return "GOAWAY"
    case 8: return "WINDOW_UPDATE"
    case 9: return "CONTINUATION"
    default: return fmt.Sprintf("TYPE%d", frameType)
    }
}

// GetHTTP2SettingName returns the name of an HTTP/2 setting.
func GetHTTP2SettingName(settingID uint16) string {
    switch settingID {
    case 0x1: return "HEADER_TABLE_SIZE"
    case 0x2: return "ENABLE_PUSH"
    case 0x3: return "MAX_CONCURRENT_STREAMS"
    case 0x4: return "INITIAL_WINDOW_SIZE"
    case 0x5: return "MAX_FRAME_SIZE"
    case 0x6: return "MAX_HEADER_LIST_SIZE"
    default: return fmt.Sprintf("UNKNOWN_SETTING_%d", settingID)
    }
}
