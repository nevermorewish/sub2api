/**
 * Admin TLS Fingerprint Profile API endpoints
 * Handles TLS fingerprint profile CRUD for administrators
 */

import { apiClient } from '../client'

/**
 * TLS fingerprint profile interface
 */
export interface TLSFingerprintProfile {
  id: number
  name: string
  description: string | null
  enable_grease: boolean
  cipher_suites: number[]
  curves: number[]
  point_formats: number[]
  signature_algorithms: number[]
  alpn_protocols: string[]
  supported_versions: number[]
  key_share_groups: number[]
  psk_modes: number[]
  extensions: number[]
  created_at: string
  updated_at: string
}

/**
 * Create profile request
 */
export interface CreateProfileRequest {
  name: string
  description?: string | null
  enable_grease?: boolean
  cipher_suites?: number[]
  curves?: number[]
  point_formats?: number[]
  signature_algorithms?: number[]
  alpn_protocols?: string[]
  supported_versions?: number[]
  key_share_groups?: number[]
  psk_modes?: number[]
  extensions?: number[]
}

/**
 * Update profile request
 */
export interface UpdateProfileRequest {
  name?: string
  description?: string | null
  enable_grease?: boolean
  cipher_suites?: number[]
  curves?: number[]
  point_formats?: number[]
  signature_algorithms?: number[]
  alpn_protocols?: string[]
  supported_versions?: number[]
  key_share_groups?: number[]
  psk_modes?: number[]
  extensions?: number[]
}

/**
 * Parameterized TLS fingerprint template generation request
 */
export interface GenerateProfileRequest {
  name?: string
  description?: string | null
  runtime?: string
  runtime_version?: string
  node_major?: number
  openssl_version?: string
  transport?: string
  http_client?: string
  websocket_client?: string
  proxy_mode?: string
  mtls_enabled?: boolean
  custom_ca_enabled?: boolean
  alpn_protocols?: string[]
  enable_grease?: boolean
}

/**
 * Generated profile response. The profile is not saved until create/update.
 */
export interface GenerateProfileResponse {
  profile: TLSFingerprintProfile
  notes: string[]
}

export async function list(): Promise<TLSFingerprintProfile[]> {
  const { data } = await apiClient.get<TLSFingerprintProfile[]>('/admin/tls-fingerprint-profiles')
  return data
}

export async function getById(id: number): Promise<TLSFingerprintProfile> {
  const { data } = await apiClient.get<TLSFingerprintProfile>(`/admin/tls-fingerprint-profiles/${id}`)
  return data
}

export async function create(profileData: CreateProfileRequest): Promise<TLSFingerprintProfile> {
  const { data } = await apiClient.post<TLSFingerprintProfile>('/admin/tls-fingerprint-profiles', profileData)
  return data
}

export async function update(id: number, updates: UpdateProfileRequest): Promise<TLSFingerprintProfile> {
  const { data } = await apiClient.put<TLSFingerprintProfile>(`/admin/tls-fingerprint-profiles/${id}`, updates)
  return data
}

export async function generate(request: GenerateProfileRequest): Promise<GenerateProfileResponse> {
  const { data } = await apiClient.post<GenerateProfileResponse>('/admin/tls-fingerprint-profiles/generate', request)
  return data
}

export async function deleteProfile(id: number): Promise<{ message: string }> {
  const { data } = await apiClient.delete<{ message: string }>(`/admin/tls-fingerprint-profiles/${id}`)
  return data
}

export const tlsFingerprintProfileAPI = {
  list,
  getById,
  create,
  update,
  generate,
  delete: deleteProfile
}

export default tlsFingerprintProfileAPI
