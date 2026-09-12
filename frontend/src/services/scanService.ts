import { api } from "./api"

/* ============================================================
   SCAN STATUS
============================================================ */

export type ScanStatus =
  | "queued"
  | "processing"
  | "completed"
  | "failed"

/* ============================================================
   MODEL SCORE
============================================================ */

export interface ModelScore {
  available: boolean
  prediction: number
  probability: number
  score?: number
}

/* ============================================================
   THREAT INTELLIGENCE
============================================================ */

export interface ThreatIntelligence {
  provider: string
  status: string
  malicious: number
  suspicious: number
  harmless: number
  undetected: number
  total_engines: number
  threat_score: number
  cached: boolean
  error: string | null
  reasons?: string[]
}

/* ============================================================
   ASYNC QUEUE RESPONSE
============================================================ */

export interface AsyncScanResponse {
  success: boolean
  message: string
  scan_id: string
  status: ScanStatus
  url: string
  created_at: string
  request_id: string
}

/* ============================================================
   COMPLETED SCAN RESULT
============================================================ */

export interface ScanResultData {
  success: boolean
  url: string

  risk: {
    score: number
    level: string
    confidence: number
  }

  prediction: string
  trusted_domain: boolean

  reasons: string[]

  models: {
    url_ml?: ModelScore
    hostname_ml?: ModelScore
    fusion_score?: number
    rule_score?: number
  }

  rules?: {
    risk_score: number
    risk_level: string
    signals: Record<string, unknown>
  }

  threat_intelligence?: ThreatIntelligence

  scan_duration_ms: number

  timestamp: string

  cache?: {
    hit: boolean
    source: string
  }

  request_id: string
}

/* ============================================================
   ASYNC STATUS RESPONSE
============================================================ */
export interface ScanStatusResponse {
  success: boolean
  scan_id: string
  status: ScanStatus

  url?: string
  created_at?: string
  updated_at?: string

  result?: ScanResultData

  error?: string
  request_id: string
  duration_ms?: number
}
export interface ScanHistoryItem {
  id: number
  url: string
  prediction: string
  risk_score: number
  risk_level: string
  confidence: number
  trusted_domain: boolean

  url_ml_score: number
  hostname_ml_score: number
  model_score: number
  rule_score: number

  threat_score: number
  vt_malicious: number
  vt_suspicious: number
  vt_harmless: number
  vt_undetected: number
  vt_total_engines: number

  threat_intel_status: string
  threat_intel_provider: string

  scan_duration_ms: number
  scanned_at: string
}

export interface ScanHistoryResponse {
  success: boolean
  count: number
  results: ScanHistoryItem[]
}


/* ============================================================
   SCAN SERVICE
============================================================ */

export const scanService = {
  async scanUrl(url: string) {
    const response = await api.post("/api/v1/scan", { url })
    return response.data
  },

  async scanUrlAsync(url: string): Promise<AsyncScanResponse> {
    const response = await api.post("/api/v1/scan/async", { url })
    return response.data
  },

  async getScanStatus(
    scanId: string,
  ): Promise<ScanStatusResponse> {
    const response = await api.get(
      `/api/v1/scan/${scanId}`,
    )
    return response.data
  },

  async getHistory(): Promise<ScanHistoryResponse> {
  const response = await api.get("/api/history")
  return response.data
},
}
