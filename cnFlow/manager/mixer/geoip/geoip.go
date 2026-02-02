// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package geoip

import (
    "fmt"
    "log"
    "net"
    "os"
    "strings"
    "sync"
    "path/filepath"
    "runtime"

    "github.com/oschwald/geoip2-golang"
    "cnFlow/protobuf"
)





type GeoIPResolver struct {
    cityDB    *geoip2.Reader
    countryDB *geoip2.Reader
    mu        sync.RWMutex
}

var GlobalResolver *GeoIPResolver





type GeoInfoCache struct {
    cache   map[string]*protobuf.GeoInfo
    mu      sync.RWMutex
    maxSize int
}

var globalCache *GeoInfoCache

// init initializes the global GeoIP cache.
func init() {
    globalCache = &GeoInfoCache{
        cache:   make(map[string]*protobuf.GeoInfo),
        maxSize: 10000,
    }
}





// InitGeoIPResolver opens the GeoIP databases and initializes the global resolver.
func InitGeoIPResolver() error {
    resolver := &GeoIPResolver{}

    // Determine GeoIP database directory:
    // 1. GEOIP_DB_DIR env var (for container/custom deployments)
    // 2. Fallback to directory containing geoip.go (for source builds)
    baseDir := os.Getenv("GEOIP_DB_DIR")
    if baseDir == "" {
        _, thisFile, _, ok := runtime.Caller(0)
        if !ok {
            return fmt.Errorf("cannot locate geoip.go and GEOIP_DB_DIR is not set")
        }
        baseDir = filepath.Dir(thisFile)
    }

    // Specify DB file paths as absolute paths
    cityPath := filepath.Join(baseDir, "GeoLite2-City.mmdb")
    countryPath := filepath.Join(baseDir, "GeoLite2-Country.mmdb")

    var err error
    resolver.cityDB, err = geoip2.Open(cityPath)
    if err != nil {
        return fmt.Errorf("open city db: %w", err)
    }

    resolver.countryDB, err = geoip2.Open(countryPath)
    if err != nil {
        resolver.cityDB.Close()
        return fmt.Errorf("open country db: %w", err)
    }

    GlobalResolver = resolver
    log.Printf("[GeoIP] GeoIP resolver initialized (DB dir: %s)", baseDir)
    return nil
}

// CloseGeoIPResolver closes the GeoIP databases and releases the global resolver.
func CloseGeoIPResolver() {
    if GlobalResolver == nil {
        return
    }

    GlobalResolver.mu.Lock()
    defer GlobalResolver.mu.Unlock()

    if GlobalResolver.cityDB != nil {
        GlobalResolver.cityDB.Close()
    }
    if GlobalResolver.countryDB != nil {
        GlobalResolver.countryDB.Close()
    }

    GlobalResolver = nil
    log.Printf("[GeoIP] GeoIP resolver closed")
}





// LookupIP performs a GeoIP lookup for the given IP address string.
func LookupIP(ipStr string) *protobuf.GeoInfo {
    if GlobalResolver == nil {
        return nil
    }

    ip := net.ParseIP(ipStr)
    if ip == nil {
        return nil
    }

    GlobalResolver.mu.RLock()
    defer GlobalResolver.mu.RUnlock()

    // Look up City in same way as example
    cityRecord, errCity := GlobalResolver.cityDB.City(ip)
    countryRecord, errCountry := GlobalResolver.countryDB.Country(ip)

    if errCity != nil && errCountry != nil {
        return nil
    }

    return convertToGeoInfo(cityRecord, countryRecord)
}





// convertToGeoInfo converts geoip2 City and Country records into a protobuf GeoInfo.
func convertToGeoInfo(city *geoip2.City, country *geoip2.Country) *protobuf.GeoInfo {
    if city == nil && country == nil {
        return nil
    }

    geoInfo := &protobuf.GeoInfo{}

    // Safe data extraction based on example approach
    if city != nil {
        // Country information (example record.Country.Names approach)
        if name, ok := city.Country.Names["en"]; ok && name != "" {
            geoInfo.Country = name
        } else if name, ok := city.Country.Names["ko"]; ok && name != "" {
            geoInfo.Country = name
        }

        // Region information (example record.Subdivisions approach)
        if len(city.Subdivisions) > 0 {
            if name, ok := city.Subdivisions[0].Names["en"]; ok && name != "" {
                geoInfo.Region = name
            } else if name, ok := city.Subdivisions[0].Names["ko"]; ok && name != "" {
                geoInfo.Region = name
            }
        }

        // City information (example record.City.Names approach)
        if name, ok := city.City.Names["en"]; ok && name != "" {
            geoInfo.City = name
        } else if name, ok := city.City.Names["ko"]; ok && name != "" {
            geoInfo.City = name
        }

        // Location and timezone information (same as example)
        geoInfo.Timezone = city.Location.TimeZone
        geoInfo.Latitude = city.Location.Latitude
        geoInfo.Longitude = city.Location.Longitude

        // GeoLite2-City does not provide ISP/AS information
        geoInfo.Isp = ""
        geoInfo.Org = ""
        geoInfo.AsName = ""
        geoInfo.AsNumber = 0
    } else if country != nil {
        // When using only Country DB (refer to example comments)
        if name, ok := country.Country.Names["en"]; ok && name != "" {
            geoInfo.Country = name
        } else if name, ok := country.Country.Names["ko"]; ok && name != "" {
            geoInfo.Country = name
        }
    }

    return geoInfo
}

// getLocalizedName returns the best available localized name from a names map.
func getLocalizedName(names map[string]string) string {
    // Safe name extraction based on example approach
    if name, ok := names["en"]; ok && name != "" {
        return name
    }
    
    if name, ok := names["ko"]; ok && name != "" {
        return name
    }
    
    // Return first available name
    for _, name := range names {
        if name != "" {
            return name
        }
    }
    
    return ""
}





// GetCachedGeoInfo retrieves cached GeoIP information for the given IP.
func GetCachedGeoInfo(ip string) (*protobuf.GeoInfo, bool) {
    if globalCache == nil {
        return nil, false
    }
    
    globalCache.mu.RLock()
    defer globalCache.mu.RUnlock()
    
    geoInfo, exists := globalCache.cache[ip]
    return geoInfo, exists
}

// SetCachedGeoInfo stores GeoIP information in the cache for the given IP.
func SetCachedGeoInfo(ip string, geoInfo *protobuf.GeoInfo) {
    if globalCache == nil || geoInfo == nil {
        return
    }
    
    globalCache.mu.Lock()
    defer globalCache.mu.Unlock()
    
    if len(globalCache.cache) >= globalCache.maxSize {
        for k := range globalCache.cache {
            delete(globalCache.cache, k)
            break
        }
    }
    
    globalCache.cache[ip] = geoInfo
}

// ClearGeoInfoCache clears all entries from the GeoIP cache.
func ClearGeoInfoCache() {
    if globalCache == nil {
        return
    }
    
    globalCache.mu.Lock()
    defer globalCache.mu.Unlock()
    
    globalCache.cache = make(map[string]*protobuf.GeoInfo)
}

// GetCacheStats returns current cache size and max size statistics.
func GetCacheStats() map[string]interface{} {
    if globalCache == nil {
        return nil
    }
    
    globalCache.mu.RLock()
    defer globalCache.mu.RUnlock()
    
    return map[string]interface{}{
        "cache_size": len(globalCache.cache),
        "max_size":   globalCache.maxSize,
    }
}





// IsValidGeoInfo checks whether the GeoInfo has at least a country set.
func IsValidGeoInfo(geoInfo *protobuf.GeoInfo) bool {
    if geoInfo == nil {
        return false
    }
    return geoInfo.Country != ""
}

// FormatLocationString formats GeoInfo into a comma-separated location string.
func FormatLocationString(geoInfo *protobuf.GeoInfo) string {
    if geoInfo == nil {
        return "Unknown"
    }
    
    var parts []string
    
    if geoInfo.City != "" {
        parts = append(parts, geoInfo.City)
    }
    
    if geoInfo.Region != "" {
        parts = append(parts, geoInfo.Region)
    }
    
    if geoInfo.Country != "" {
        parts = append(parts, geoInfo.Country)
    }
    
    if len(parts) == 0 {
        return "Unknown"
    }
    
    return strings.Join(parts, ", ")
}

// GetCoordinatesString returns a formatted latitude/longitude string from GeoInfo.
func GetCoordinatesString(geoInfo *protobuf.GeoInfo) string {
    if geoInfo == nil || (geoInfo.Latitude == 0 && geoInfo.Longitude == 0) {
        return ""
    }
    
    return fmt.Sprintf("%.6f, %.6f", geoInfo.Latitude, geoInfo.Longitude)
}

// IsInternationalLocation checks whether two GeoInfo records represent different countries.
func IsInternationalLocation(geo1, geo2 *protobuf.GeoInfo) bool {
    if geo1 == nil || geo2 == nil {
        return false
    }
    
    return geo1.Country != "" && geo2.Country != "" && geo1.Country != geo2.Country
}

// GetTimezoneOffset returns a description of the timezone difference between two GeoInfo records.
func GetTimezoneOffset(geo1, geo2 *protobuf.GeoInfo) string {
    if geo1 == nil || geo2 == nil {
        return ""
    }
    
    if geo1.Timezone == "" || geo2.Timezone == "" {
        return ""
    }
    
    if geo1.Timezone == geo2.Timezone {
        return fmt.Sprintf("Same timezone (%s)", geo1.Timezone)
    }
    
    return fmt.Sprintf("%s -> %s", geo1.Timezone, geo2.Timezone)
}
