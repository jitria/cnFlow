// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package protocol

import (
    "fmt"
    "strings"

    "cnFlow/protobuf"
)

// HTTPAnalysisResult contains all analysis results from an HTTP event.
type HTTPAnalysisResult struct {
    // Basic network information
    BaseInfo *BaseNetworkInfo `json:"base_info"`

    // HTTP protocol information
    Method      string `json:"method"`
    URI         string `json:"uri"`
    StatusCode  string `json:"status_code"`
    IsRequest   bool   `json:"is_request"`

    // Detailed analysis by request/response
    RequestAnalysis  *HTTPRequestAnalysis  `json:"request_analysis,omitempty"`
    ResponseAnalysis *HTTPResponseAnalysis `json:"response_analysis,omitempty"`

    // URI analysis (if request)
    URIAnalysis *HTTPURIAnalysis `json:"uri_analysis,omitempty"`
}

type HTTPRequestAnalysis struct {
    Method      string `json:"method"`
    MethodType  string `json:"method_type"`
    Purpose     string `json:"purpose"`
}

type HTTPResponseAnalysis struct {
    StatusCode    string `json:"status_code"`
    StatusNumber  int    `json:"status_number"`
    StatusText    string `json:"status_text"`
    Category      string `json:"category"`
    Class         string `json:"class"`
    Description   string `json:"description"`
}

type HTTPURIAnalysis struct {
    OriginalURI    string                 `json:"original_uri"`
    Scheme         string                 `json:"scheme"`
    Authority      string                 `json:"authority,omitempty"`
    Host           string                 `json:"host,omitempty"`
    Port           string                 `json:"port,omitempty"`
    Path           string                 `json:"path"`
    QueryString    string                 `json:"query_string,omitempty"`
    Fragment       string                 `json:"fragment,omitempty"`
    FileExtension  string                 `json:"file_extension,omitempty"`
    PathDepth      int                    `json:"path_depth"`
    Parameters     map[string]string      `json:"parameters,omitempty"`
    ParameterCount int                    `json:"parameter_count"`
}

// AnalyzeHTTPEventDetailed analyzes an HTTP event and returns all results.
func AnalyzeHTTPEventDetailed(event *protobuf.HTTPEvent) *HTTPAnalysisResult {
    result := &HTTPAnalysisResult{
        // Basic network information
        BaseInfo: ParseBaseNetworkInfo(event.Base),

        // HTTP protocol information
        Method:     event.Method,
        URI:        event.Uri,
        StatusCode: event.StatusCode,
        IsRequest:  event.IsRequest,
    }

    // Detailed analysis by request/response
    if event.IsRequest {
        result.RequestAnalysis = analyzeHTTPRequest(event)
        result.URIAnalysis = analyzeHTTPURI(event.Uri)
    } else {
        result.ResponseAnalysis = analyzeHTTPResponse(event)
    }

    return result
}

// analyzeHTTPRequest analyzes an HTTP request method and determines its purpose.
func analyzeHTTPRequest(event *protobuf.HTTPEvent) *HTTPRequestAnalysis {
    analysis := &HTTPRequestAnalysis{
        Method: event.Method,
    }
    
    switch strings.ToUpper(event.Method) {
    case "GET":
        analysis.MethodType = "Data Retrieval"
        analysis.Purpose = "Retrieve resource"
    case "POST":
        analysis.MethodType = "Data Submission"
        analysis.Purpose = "Submit/create data"
    case "PUT":
        analysis.MethodType = "Data Update/Create"
        analysis.Purpose = "Update/replace resource"
    case "DELETE":
        analysis.MethodType = "Data Deletion"
        analysis.Purpose = "Delete resource"
    case "HEAD":
        analysis.MethodType = "Metadata Retrieval"
        analysis.Purpose = "Get headers only"
    case "OPTIONS":
        analysis.MethodType = "Method Discovery"
        analysis.Purpose = "Discover allowed methods"
    case "PATCH":
        analysis.MethodType = "Partial Update"
        analysis.Purpose = "Partial resource update"
    case "TRACE":
        analysis.MethodType = "Diagnostic"
        analysis.Purpose = "Diagnostic trace"
    case "CONNECT":
        analysis.MethodType = "Tunnel Establishment"
        analysis.Purpose = "Establish tunnel"
    default:
        analysis.MethodType = "Custom Method"
        analysis.Purpose = "Custom operation"
    }
    
    return analysis
}

// analyzeHTTPResponse parses the HTTP status code and categorizes the response.
func analyzeHTTPResponse(event *protobuf.HTTPEvent) *HTTPResponseAnalysis {
    analysis := &HTTPResponseAnalysis{
        StatusCode: event.StatusCode,
    }

    if event.StatusCode == "" {
        analysis.Description = "Empty status code"
        return analysis
    }

    // Parse status code number
    var statusNum int
    if len(event.StatusCode) >= 3 {
        statusStr := event.StatusCode[:3]
        if num := ParseInt(statusStr); num > 0 {
            statusNum = num
        }
    }
    
    if statusNum > 0 {
        analysis.StatusNumber = statusNum
        analysis.StatusText = getHTTPStatusText(statusNum)
        analysis.Category = getStatusCategory(statusNum)
        analysis.Class = fmt.Sprintf("%dxx", statusNum/100)
        analysis.Description = getStatusDescription(statusNum)
    } else {
        analysis.Description = "Could not parse as number"
    }
    
    return analysis
}

// analyzeHTTPURI parses and analyzes an HTTP URI into its components.
func analyzeHTTPURI(uri string) *HTTPURIAnalysis {
    analysis := &HTTPURIAnalysis{
        OriginalURI: uri,
        Parameters:  make(map[string]string),
    }
    
    originalURI := uri

    // Parse scheme
    var scheme string
    if strings.HasPrefix(uri, "http://") {
        scheme = "http"
        uri = strings.TrimPrefix(uri, "http://")
    } else if strings.HasPrefix(uri, "https://") {
        scheme = "https"
        uri = strings.TrimPrefix(uri, "https://")
    } else {
        scheme = "relative"
    }
    analysis.Scheme = scheme

    // Parse authority (host)
    var authority, path string
    if scheme != "relative" && strings.Contains(uri, "/") {
        parts := strings.SplitN(uri, "/", 2)
        authority = parts[0]
        path = "/" + parts[1]
    } else {
        path = uri
    }

    if authority != "" {
        analysis.Authority = authority

        // Split host and port
        if strings.Contains(authority, ":") {
            hostParts := strings.Split(authority, ":")
            analysis.Host = hostParts[0]
            analysis.Port = hostParts[1]
        } else {
            analysis.Host = authority
        }
    }

    // Parse path and query
    var actualPath, queryString string
    if strings.Contains(path, "?") {
        parts := strings.Split(path, "?")
        actualPath = parts[0]
        queryString = parts[1]
    } else {
        actualPath = path
    }

    analysis.Path = actualPath

    if queryString != "" {
        analysis.QueryString = queryString

        // Parse query parameters
        params := strings.Split(queryString, "&")
        analysis.ParameterCount = len(params)

        for _, param := range params {
            if strings.Contains(param, "=") {
                kv := strings.SplitN(param, "=", 2)
                analysis.Parameters[kv[0]] = kv[1]
            } else {
                analysis.Parameters[param] = ""
            }
        }
    }

    // Parse fragment (after #)
    if strings.Contains(originalURI, "#") {
        parts := strings.Split(originalURI, "#")
        if len(parts) > 1 {
            analysis.Fragment = parts[1]
        }
    }

    // Parse file extension
    pathParts := strings.Split(actualPath, "/")
    if len(pathParts) > 0 {
        lastPart := pathParts[len(pathParts)-1]
        if strings.Contains(lastPart, ".") {
            extParts := strings.Split(lastPart, ".")
            if len(extParts) > 1 {
                analysis.FileExtension = extParts[len(extParts)-1]
            }
        }
    }

    // Path depth
    analysis.PathDepth = strings.Count(actualPath, "/")
    
    return analysis
}

// getStatusCategory returns the HTTP status category for a status code.
func getStatusCategory(statusCode int) string {
    switch {
    case statusCode >= 100 && statusCode < 200: return "Informational"
    case statusCode >= 200 && statusCode < 300: return "Success"
    case statusCode >= 300 && statusCode < 400: return "Redirection"
    case statusCode >= 400 && statusCode < 500: return "Client Error"
    case statusCode >= 500 && statusCode < 600: return "Server Error"
    default: return "Unknown"
    }
}

// getHTTPStatusText returns the standard text for an HTTP status code.
func getHTTPStatusText(statusCode int) string {
    switch statusCode {
    case 200: return "OK"
    case 201: return "Created"
    case 204: return "No Content"
    case 301: return "Moved Permanently"
    case 302: return "Found"
    case 304: return "Not Modified"
    case 400: return "Bad Request"
    case 401: return "Unauthorized"
    case 403: return "Forbidden"
    case 404: return "Not Found"
    case 429: return "Too Many Requests"
    case 500: return "Internal Server Error"
    case 502: return "Bad Gateway"
    case 503: return "Service Unavailable"
    case 504: return "Gateway Timeout"
    default: return fmt.Sprintf("Status%d", statusCode)
    }
}

// getStatusDescription returns a descriptive string for an HTTP status code.
func getStatusDescription(statusCode int) string {
    switch statusCode {
    case 200: return "OK - Request successful"
    case 201: return "Created - Resource created"
    case 204: return "No Content"
    case 301: return "Moved Permanently"
    case 302: return "Found (Temporary Redirect)"
    case 304: return "Not Modified"
    case 400: return "Bad Request"
    case 401: return "Unauthorized"
    case 403: return "Forbidden"
    case 404: return "Not Found"
    case 429: return "Too Many Requests"
    case 500: return "Internal Server Error"
    case 502: return "Bad Gateway"
    case 503: return "Service Unavailable"
    case 504: return "Gateway Timeout"
    default: return getHTTPStatusText(statusCode)
    }
}
