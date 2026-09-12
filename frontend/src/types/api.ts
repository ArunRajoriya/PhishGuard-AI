export interface ScanRequest {
  url: string
}

export interface RiskInfo {
  score: number
  level: string
  confidence: number
}

export interface ModelScore {
  available: boolean
  prediction?: number | null
  probability?: number | null
  score?: number | null
}

export interface ModelScores {
  url_ml?: ModelScore | null
  hostname_ml?: ModelScore | null
  fusion_score?: number | null
  rule_score?: number | null
}

export interface ThreatIntelligence {
  provider?: string
  status?: string
  malicious?: number
  suspicious?: number
  harmless?: number
  undetected?: number
  total_engines?: number
  threat_score?: number
  cached?: boolean
  error?: string | null
  reasons?: string[]
}

export interface CacheInfo {
  hit?: boolean
  source?: string
}

export interface RateLimitInfo {
  limit?: number
  remaining?: number
  reset_after?: number
}

export interface ScanResponse {
  success?: boolean
  url: string
  risk: RiskInfo
  prediction: string
  trusted_domain: boolean
  reasons?: string[]
  models: ModelScores
  threat_intelligence?: ThreatIntelligence
  scan_duration_ms: number
  timestamp: string
  cache: CacheInfo
  request_id: string
  rate_limit?: RateLimitInfo
}