// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package mixer

import (
    "fmt"
    "log"
    "strings"
    "cnFlow/protobuf"
    "cnFlow/manager/mixer/geoip"
)

// GeographicAnalyzer manages geographic information analysis.
type GeographicAnalyzer struct {
    // Country statistics
    CountryStats map[string]*CountryStatistics

    // Region statistics
    RegionStats  map[string]*RegionStatistics

    // ISP statistics
    ISPStats     map[string]*ISPStatistics
}

// CountryStatistics stores country-level statistics.
type CountryStatistics struct {
    Country        string
    TotalFlows     int64
    InternalFlows  int64  // Domestic communication
    InboundFlows   int64  // Incoming international communication
    OutboundFlows  int64  // Outgoing international communication
    TopRegions     map[string]int64
    TopISPs        map[string]int64
}

// RegionStatistics stores region-level statistics.
type RegionStatistics struct {
    Country     string
    Region      string
    TotalFlows  int64
    TopCities   map[string]int64
}

// ISPStatistics stores ISP-level statistics.
type ISPStatistics struct {
    ISPName     string
    Organization string
    TotalFlows  int64
    Countries   map[string]int64
    ASNumbers   map[int32]string
}

// FlowGeography contains geographic information for individual flows.
type FlowGeography struct{
    SourceLocation      *LocationInfo
    DestinationLocation *LocationInfo
    FlowType           GeographicFlowType
    TimezoneInfo       *TimezoneInfo
    NetworkInfo        *NetworkProviderInfo
}

// LocationInfo contains location information.
type LocationInfo struct{
    Country   string
    Region    string
    City      string
    Timezone  string
    ISP       string
    Org       string
    ASName    string
    ASNumber  int32
}

// TimezoneInfo contains timezone information.
type TimezoneInfo struct {
    SourceTimezone      string
    DestinationTimezone string
    HasTimezoneDiff     bool
    TimezoneDescription string
}

// NetworkProviderInfo contains network provider information.
type NetworkProviderInfo struct {
    SourceISP      string
    DestinationISP string
    SourceAS       string
    DestinationAS  string
    SameProvider   bool
    SameAS         bool
}

// GeographicFlowType defines the geographic flow type.
type GeographicFlowType int

const (
    FlowTypeUnknown GeographicFlowType = iota
    FlowTypeDomestic                   // Domestic communication
    FlowTypeInternational              // International communication
    FlowTypeRegional                   // Same region communication
    FlowTypeContinental                // Same continent communication
    FlowTypeIntercontinental           // Intercontinental communication
)

var GlobalGeoAnalyzer *GeographicAnalyzer

// init initializes the global geographic analyzer.
func init() {
    GlobalGeoAnalyzer = NewGeographicAnalyzer()
}

// NewGeographicAnalyzer creates a new geographic analyzer.
func NewGeographicAnalyzer() *GeographicAnalyzer {
    return &GeographicAnalyzer{
        CountryStats: make(map[string]*CountryStatistics),
        RegionStats:  make(map[string]*RegionStatistics),
        ISPStats:     make(map[string]*ISPStatistics),
    }
}

// AnalyzeFlowGeography analyzes geographic information for source and destination (with external IP support).
func AnalyzeFlowGeography(srcNode, dstNode *protobuf.NodeInfo, srcIP, dstIP string) *FlowGeography {
    geo := &FlowGeography{}
    
    // Extract source location information
    if srcNode != nil && srcNode.GeoInfo != nil {
        // Use geographic info from internal cluster node
        geo.SourceLocation = extractLocationInfo(srcNode.GeoInfo)
    } else if srcIP != "" {
        // Perform GeoIP lookup for external IP (cache first)
        if cachedGeo, found := geoip.GetCachedGeoInfo(srcIP); found {
            geo.SourceLocation = extractLocationInfo(cachedGeo)
        } else if geoInfo := geoip.LookupIP(srcIP); geoInfo != nil {
            geo.SourceLocation = extractLocationInfo(geoInfo)
            // Store lookup result in cache
            geoip.SetCachedGeoInfo(srcIP, geoInfo)
        }
    }
    
    // Extract destination location information
    if dstNode != nil && dstNode.GeoInfo != nil {
        // Use geographic info from internal cluster node
        geo.DestinationLocation = extractLocationInfo(dstNode.GeoInfo)
    } else if dstIP != "" {
        // Perform GeoIP lookup for external IP (cache first)
        if cachedGeo, found := geoip.GetCachedGeoInfo(dstIP); found {
            geo.DestinationLocation = extractLocationInfo(cachedGeo)
        } else if geoInfo := geoip.LookupIP(dstIP); geoInfo != nil {
            geo.DestinationLocation = extractLocationInfo(geoInfo)
            // Store lookup result in cache
            geoip.SetCachedGeoInfo(dstIP, geoInfo)
        }
    }
    
    // Determine flow type
    geo.FlowType = determineFlowType(geo.SourceLocation, geo.DestinationLocation)

    // Analyze timezone information
    geo.TimezoneInfo = analyzeTimezones(geo.SourceLocation, geo.DestinationLocation)

    // Analyze network provider information
    geo.NetworkInfo = analyzeNetworkProviders(geo.SourceLocation, geo.DestinationLocation)
    
    // Update statistics
    GlobalGeoAnalyzer.updateStatistics(geo)
    
    return geo
}

// AnalyzeFlowGeographyLegacy is a wrapper function for backward compatibility.
func AnalyzeFlowGeographyLegacy(srcNode, dstNode *protobuf.NodeInfo) *FlowGeography {
    return AnalyzeFlowGeography(srcNode, dstNode, "", "")
}

// extractLocationInfo extracts LocationInfo from GeoInfo.
func extractLocationInfo(geoInfo *protobuf.GeoInfo) *LocationInfo {
    if geoInfo == nil {
        return nil
    }
    
    return &LocationInfo{
        Country:  geoInfo.Country,
        Region:   geoInfo.Region,
        City:     geoInfo.City,
        Timezone: geoInfo.Timezone,
        ISP:      geoInfo.Isp,
        Org:      geoInfo.Org,
        ASName:   geoInfo.AsName,
        ASNumber: geoInfo.AsNumber,
    }
}

// determineFlowType determines the geographic type of a flow.
func determineFlowType(src, dst *LocationInfo) GeographicFlowType {
    if src == nil || dst == nil {
        return FlowTypeUnknown
    }
    
    // Check if same country
    if src.Country == dst.Country {
        if src.Region == dst.Region {
            return FlowTypeRegional
        }
        return FlowTypeDomestic
    }
    
    // International communication
    if isSameContinent(src.Country, dst.Country) {
        return FlowTypeContinental
    }
    
    return FlowTypeIntercontinental
}

// analyzeTimezones analyzes timezone information.
func analyzeTimezones(src, dst *LocationInfo) *TimezoneInfo {
    info := &TimezoneInfo{}
    
    if src != nil {
        info.SourceTimezone = src.Timezone
    }
    
    if dst != nil {
        info.DestinationTimezone = dst.Timezone
    }
    
    if src != nil && dst != nil {
        info.HasTimezoneDiff = src.Timezone != dst.Timezone
        if info.HasTimezoneDiff {
            info.TimezoneDescription = fmt.Sprintf("%s -> %s", src.Timezone, dst.Timezone)
        } else {
            info.TimezoneDescription = fmt.Sprintf("Same timezone (%s)", src.Timezone)
        }
    }
    
    return info
}

// analyzeNetworkProviders analyzes network provider information.
func analyzeNetworkProviders(src, dst *LocationInfo) *NetworkProviderInfo {
    info := &NetworkProviderInfo{}
    
    if src != nil {
        info.SourceISP = src.ISP
        if src.ASNumber > 0 {
            info.SourceAS = fmt.Sprintf("%s (AS%d)", src.ASName, src.ASNumber)
        } else {
            info.SourceAS = src.ASName
        }
    }
    
    if dst != nil {
        info.DestinationISP = dst.ISP
        if dst.ASNumber > 0 {
            info.DestinationAS = fmt.Sprintf("%s (AS%d)", dst.ASName, dst.ASNumber)
        } else {
            info.DestinationAS = dst.ASName
        }
    }
    
    if src != nil && dst != nil {
        info.SameProvider = src.ISP == dst.ISP && src.ISP != ""
        info.SameAS = src.ASNumber == dst.ASNumber && src.ASNumber > 0
    }
    
    return info
}





// IsExternalIP checks if an IP is external to the cluster.
func IsExternalIP(ip string) bool {
    // Check private IP ranges
    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    if strings.HasPrefix(ip, "10.") {
        return false
    }
    if strings.HasPrefix(ip, "192.168.") {
        return false
    }
    if strings.HasPrefix(ip, "172.") {
        // Check 172.16.0.0/12 range (simplified approach)
        return false
    }
    if strings.HasPrefix(ip, "127.") {
        return false // Localhost
    }
    if strings.HasPrefix(ip, "169.254.") {
        return false // Link local
    }
    
    return true
}

// GetLocationSummary converts LocationInfo to a summary string.
func GetLocationSummary(loc *LocationInfo) string {
    if loc == nil {
        return "Unknown"
    }
    
    var parts []string
    if loc.City != "" {
        parts = append(parts, loc.City)
    }
    if loc.Region != "" {
        parts = append(parts, loc.Region)
    }
    if loc.Country != "" {
        parts = append(parts, loc.Country)
    }
    
    if len(parts) == 0 {
        return "Unknown"
    }
    
    return strings.Join(parts, ", ")
}





// updateStatistics updates country, region, and ISP statistics from a flow.
func (ga *GeographicAnalyzer) updateStatistics(geo *FlowGeography) {
    if ga == nil || geo == nil {
        return
    }
    
    // Update country statistics
    ga.updateCountryStatistics(geo)
    
    // Update region statistics
    ga.updateRegionStatistics(geo)
    
    // Update ISP statistics
    ga.updateISPStatistics(geo)
}

// updateCountryStatistics updates per-country flow statistics.
func (ga *GeographicAnalyzer) updateCountryStatistics(geo *FlowGeography) {
    if geo.SourceLocation != nil && geo.SourceLocation.Country != "" {
        country := geo.SourceLocation.Country
        if stats, exists := ga.CountryStats[country]; exists {
            stats.TotalFlows++
        } else {
            ga.CountryStats[country] = &CountryStatistics{
                Country:    country,
                TotalFlows: 1,
                TopRegions: make(map[string]int64),
                TopISPs:    make(map[string]int64),
            }
        }
        
        // Statistics by flow type
        stats := ga.CountryStats[country]
        switch geo.FlowType {
        case FlowTypeDomestic, FlowTypeRegional:
            stats.InternalFlows++
        case FlowTypeInternational, FlowTypeContinental, FlowTypeIntercontinental:
            stats.OutboundFlows++
        }
        
        // Region statistics
        if geo.SourceLocation.Region != "" {
            stats.TopRegions[geo.SourceLocation.Region]++
        }
        
        // ISP statistics
        if geo.SourceLocation.ISP != "" {
            stats.TopISPs[geo.SourceLocation.ISP]++
        }
    }
    
    if geo.DestinationLocation != nil && geo.DestinationLocation.Country != "" && 
       geo.FlowType != FlowTypeDomestic && geo.FlowType != FlowTypeRegional {
        country := geo.DestinationLocation.Country
        if stats, exists := ga.CountryStats[country]; exists {
            stats.InboundFlows++
        } else {
            ga.CountryStats[country] = &CountryStatistics{
                Country:       country,
                InboundFlows:  1,
                TopRegions:    make(map[string]int64),
                TopISPs:       make(map[string]int64),
            }
        }
    }
}

// updateRegionStatistics updates per-region flow statistics.
func (ga *GeographicAnalyzer) updateRegionStatistics(geo *FlowGeography) {
    if geo.SourceLocation != nil && geo.SourceLocation.Region != "" && geo.SourceLocation.Country != "" {
        key := geo.SourceLocation.Country + "/" + geo.SourceLocation.Region
        if stats, exists := ga.RegionStats[key]; exists {
            stats.TotalFlows++
        } else {
            ga.RegionStats[key] = &RegionStatistics{
                Country:    geo.SourceLocation.Country,
                Region:     geo.SourceLocation.Region,
                TotalFlows: 1,
                TopCities:  make(map[string]int64),
            }
        }
        
        // City statistics
        if geo.SourceLocation.City != "" {
            ga.RegionStats[key].TopCities[geo.SourceLocation.City]++
        }
    }
}

// updateISPStatistics updates per-ISP flow statistics.
func (ga *GeographicAnalyzer) updateISPStatistics(geo *FlowGeography) {
    if geo.SourceLocation != nil && geo.SourceLocation.ISP != "" {
        isp := geo.SourceLocation.ISP
        if stats, exists := ga.ISPStats[isp]; exists {
            stats.TotalFlows++
        } else {
            ga.ISPStats[isp] = &ISPStatistics{
                ISPName:      isp,
                Organization: geo.SourceLocation.Org,
                TotalFlows:   1,
                Countries:    make(map[string]int64),
                ASNumbers:    make(map[int32]string),
            }
        }
        
        // Country statistics
        if geo.SourceLocation.Country != "" {
            ga.ISPStats[isp].Countries[geo.SourceLocation.Country]++
        }
        
        // AS number statistics
        if geo.SourceLocation.ASNumber > 0 {
            ga.ISPStats[isp].ASNumbers[geo.SourceLocation.ASNumber] = geo.SourceLocation.ASName
        }
    }
}





// GetFlowTypeString returns the flow type as a string.
func (ft GeographicFlowType) String() string {
    switch ft {
    case FlowTypeDomestic:
        return "Domestic"
    case FlowTypeInternational:
        return "International"
    case FlowTypeRegional:
        return "Regional"
    case FlowTypeContinental:
        return "Continental"
    case FlowTypeIntercontinental:
        return "Intercontinental"
    default:
        return "Unknown"
    }
}

// GetGeographicSummary returns a geographic information summary.
func (geo *FlowGeography) GetGeographicSummary() string {
    if geo == nil {
        return "No geographic data"
    }
    
    if geo.SourceLocation != nil && geo.DestinationLocation != nil {
        return fmt.Sprintf("%s (%s -> %s)", 
            geo.FlowType.String(),
            geo.SourceLocation.Country,
            geo.DestinationLocation.Country)
    } else if geo.SourceLocation != nil {
        return fmt.Sprintf("From %s", geo.SourceLocation.Country)
    } else if geo.DestinationLocation != nil {
        return fmt.Sprintf("To %s", geo.DestinationLocation.Country)
    }
    
    return "Unknown locations"
}

// LogGeographicAnalysis logs geographic analysis results.
func (geo *FlowGeography) LogGeographicAnalysis() {
    if geo == nil {
        return
    }
    
    log.Printf("Geographic Analysis:")
    log.Printf("  Flow Type: %s", geo.FlowType.String())
    
    // Source location information
    if geo.SourceLocation != nil {
        log.Printf("  Source Location:")
        log.Printf("    Location: %s", GetLocationSummary(geo.SourceLocation))
        if geo.SourceLocation.Timezone != "" {
            log.Printf("    Timezone: %s", geo.SourceLocation.Timezone)
        }
        if geo.SourceLocation.ISP != "" {
            log.Printf("    ISP: %s", geo.SourceLocation.ISP)
            if geo.SourceLocation.Org != "" {
                log.Printf("    Organization: %s", geo.SourceLocation.Org)
            }
        }
        if geo.SourceLocation.ASNumber > 0 {
            log.Printf("    AS: %s (AS%d)", geo.SourceLocation.ASName, geo.SourceLocation.ASNumber)
        }
    }
    
    // Destination location information
    if geo.DestinationLocation != nil {
        log.Printf("  Destination Location:")
        log.Printf("    Location: %s", GetLocationSummary(geo.DestinationLocation))
        if geo.DestinationLocation.Timezone != "" {
            log.Printf("    Timezone: %s", geo.DestinationLocation.Timezone)
        }
        if geo.DestinationLocation.ISP != "" {
            log.Printf("    ISP: %s", geo.DestinationLocation.ISP)
            if geo.DestinationLocation.Org != "" {
                log.Printf("    Organization: %s", geo.DestinationLocation.Org)
            }
        }
        if geo.DestinationLocation.ASNumber > 0 {
            log.Printf("    AS: %s (AS%d)", geo.DestinationLocation.ASName, geo.DestinationLocation.ASNumber)
        }
    }
    
    // Timezone information
    if geo.TimezoneInfo != nil && geo.TimezoneInfo.TimezoneDescription != "" {
        log.Printf("  Timezone Info: %s", geo.TimezoneInfo.TimezoneDescription)
    }
    
    // Network provider information
    if geo.NetworkInfo != nil {
        if geo.NetworkInfo.SameProvider {
            log.Printf("  Network: Same ISP (%s)", geo.NetworkInfo.SourceISP)
        } else if geo.NetworkInfo.SourceISP != "" || geo.NetworkInfo.DestinationISP != "" {
            log.Printf("  Network: Different ISPs")
            if geo.NetworkInfo.SourceISP != "" {
                log.Printf("    Source ISP: %s", geo.NetworkInfo.SourceISP)
            }
            if geo.NetworkInfo.DestinationISP != "" {
                log.Printf("    Destination ISP: %s", geo.NetworkInfo.DestinationISP)
            }
        }
        
        if geo.NetworkInfo.SameAS {
            log.Printf("  AS: Same AS (%s)", geo.NetworkInfo.SourceAS)
        } else if geo.NetworkInfo.SourceAS != "" || geo.NetworkInfo.DestinationAS != "" {
            if geo.NetworkInfo.SourceAS != "" && geo.NetworkInfo.DestinationAS != "" {
                log.Printf("  AS: Different AS (%s -> %s)", geo.NetworkInfo.SourceAS, geo.NetworkInfo.DestinationAS)
            }
        }
    }
}





// GetGlobalGeographicStats returns global geographic statistics.
func (ga *GeographicAnalyzer) GetGlobalGeographicStats() map[string]interface{} {
    if ga == nil {
        return nil
    }
    
    stats := map[string]interface{}{
        "total_countries": len(ga.CountryStats),
        "total_regions":   len(ga.RegionStats),
        "total_isps":      len(ga.ISPStats),
    }
    
    // Top countries
    topCountries := ga.getTopCountries(5)
    if len(topCountries) > 0 {
        stats["top_countries"] = topCountries
    }
    
    // Top ISPs
    topISPs := ga.getTopISPs(5)
    if len(topISPs) > 0 {
        stats["top_isps"] = topISPs
    }
    
    return stats
}

// getTopCountries returns the top N countries by flow count.
func (ga *GeographicAnalyzer) getTopCountries(limit int) []map[string]interface{} {
    type countryFlow struct {
        country string
        flows   int64
    }
    
    var countries []countryFlow
    for country, stats := range ga.CountryStats {
        countries = append(countries, countryFlow{
            country: country,
            flows:   stats.TotalFlows,
        })
    }
    
    // Simple sorting (bubble sort)
    for i := 0; i < len(countries)-1; i++ {
        for j := 0; j < len(countries)-i-1; j++ {
            if countries[j].flows < countries[j+1].flows {
                countries[j], countries[j+1] = countries[j+1], countries[j]
            }
        }
    }
    
    // Return top N items
    if limit > len(countries) {
        limit = len(countries)
    }
    
    result := make([]map[string]interface{}, limit)
    for i := 0; i < limit; i++ {
        result[i] = map[string]interface{}{
            "country": countries[i].country,
            "flows":   countries[i].flows,
        }
    }
    
    return result
}

// getTopISPs returns the top N ISPs by flow count.
func (ga *GeographicAnalyzer) getTopISPs(limit int) []map[string]interface{} {
    type ispFlow struct {
        isp   string
        flows int64
    }
    
    var isps []ispFlow
    for isp, stats := range ga.ISPStats {
        isps = append(isps, ispFlow{
            isp:   isp,
            flows: stats.TotalFlows,
        })
    }
    
    // Simple sorting
    for i := 0; i < len(isps)-1; i++ {
        for j := 0; j < len(isps)-i-1; j++ {
            if isps[j].flows < isps[j+1].flows {
                isps[j], isps[j+1] = isps[j+1], isps[j]
            }
        }
    }
    
    // Return top N items
    if limit > len(isps) {
        limit = len(isps)
    }
    
    result := make([]map[string]interface{}, limit)
    for i := 0; i < limit; i++ {
        result[i] = map[string]interface{}{
            "isp":   isps[i].isp,
            "flows": isps[i].flows,
        }
    }
    
    return result
}





// isSameContinent checks if two countries are on the same continent.
func isSameContinent(country1, country2 string) bool {
    // Extended continent mapping
    continentMap := map[string]string{
        // Asia
        "South Korea": "Asia",
        "Japan":       "Asia",
        "China":       "Asia",
        "India":       "Asia",
        "Singapore":   "Asia",
        "Thailand":    "Asia",
        "Vietnam":     "Asia",
        "Indonesia":   "Asia",
        "Malaysia":    "Asia",
        "Philippines": "Asia",
        
        // North America
        "United States": "North America",
        "Canada":        "North America",
        "Mexico":        "North America",
        
        // Europe
        "Germany":        "Europe",
        "France":         "Europe",
        "United Kingdom": "Europe",
        "Italy":          "Europe",
        "Spain":          "Europe",
        "Netherlands":    "Europe",
        "Sweden":         "Europe",
        "Norway":         "Europe",
        "Denmark":        "Europe",
        "Finland":        "Europe",
        "Poland":         "Europe",
        "Russia":         "Europe",
        
        // Oceania
        "Australia":    "Oceania",
        "New Zealand":  "Oceania",
        
        // South America
        "Brazil":     "South America",
        "Argentina":  "South America",
        "Chile":      "South America",
        "Colombia":   "South America",
        
        // Africa
        "South Africa": "Africa",
        "Nigeria":      "Africa",
        "Egypt":        "Africa",
        "Kenya":        "Africa",
    }
    
    continent1, exists1 := continentMap[country1]
    continent2, exists2 := continentMap[country2]
    
    if !exists1 || !exists2 {
        return false
    }
    
    return continent1 == continent2
}

// IsInternationalFlow checks if this is international communication.
func (geo *FlowGeography) IsInternationalFlow() bool {
    return geo.FlowType == FlowTypeInternational || 
           geo.FlowType == FlowTypeContinental || 
           geo.FlowType == FlowTypeIntercontinental
}

// HasTimezoneChange checks if there is a timezone change.
func (geo *FlowGeography) HasTimezoneChange() bool {
    return geo.TimezoneInfo != nil && geo.TimezoneInfo.HasTimezoneDiff
}

// IsSameNetworkProvider checks if using the same network provider.
func (geo *FlowGeography) IsSameNetworkProvider() bool {
    return geo.NetworkInfo != nil && geo.NetworkInfo.SameProvider
}

// GetFlowDescription returns a description of the flow.
func (geo *FlowGeography) GetFlowDescription() string {
    if geo == nil {
        return "Unknown flow"
    }
    
    var parts []string
    
    // Flow type
    parts = append(parts, geo.FlowType.String())
    
    // Location information
    if geo.SourceLocation != nil && geo.DestinationLocation != nil {
        parts = append(parts, fmt.Sprintf("from %s to %s", 
            geo.SourceLocation.Country, geo.DestinationLocation.Country))
    }
    
    // Timezone information
    if geo.HasTimezoneChange() {
        parts = append(parts, "with timezone change")
    }
    
    // Network provider
    if geo.IsSameNetworkProvider() {
        parts = append(parts, "same ISP")
    }
    
    return strings.Join(parts, " ")
}
