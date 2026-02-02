// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package attacher

import (
    "fmt"
    "strings"
)

// cleanString removes non-printable characters and trims spaces and null bytes
func cleanString(s string) string {
    cleaned := strings.TrimSpace(strings.Trim(s, "\x00"))
    var result strings.Builder
    for _, char := range cleaned {
        if char >= 32 && char <= 126 {
            result.WriteRune(char)
        }
    }
    return result.String()
}

// ipToStr converts a uint32 IP address to dotted decimal string
func ipToStr(ip uint32) string {
    return fmt.Sprintf("%d.%d.%d.%d",
        byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

// portToStr formats port number
func portToStr(port uint16) string {
    return fmt.Sprintf("%d", port)
}

// timestampToStr formats timestamp (nanoseconds) to readable string
func timestampToStr(timestampNs uint64) string {
    seconds := timestampNs / 1000000000
    nanoseconds := timestampNs % 1000000000
    return fmt.Sprintf("%d.%09d", seconds, nanoseconds)
}

// getHTTPStatusText returns HTTP status text from status code
func getHTTPStatusText(statusCode int) string {
    switch statusCode {
    case 200:
        return "OK"
    case 201:
        return "Created"
    case 400:
        return "Bad Request"
    case 401:
        return "Unauthorized"
    case 403:
        return "Forbidden"
    case 404:
        return "Not Found"
    case 500:
        return "Internal Server Error"
    case 502:
        return "Bad Gateway"
    case 503:
        return "Service Unavailable"
    default:
        return fmt.Sprintf("Status%d", statusCode)
    }
}

// bytesToHex converts byte array to hex string for debugging
func bytesToHex(data []byte, maxLen int) string {
    if len(data) > maxLen {
        data = data[:maxLen]
    }
    return fmt.Sprintf("%x", data)
}
