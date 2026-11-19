import { API_URL } from './config'

export type ApiAlert = {
  id: number | string
  rule_name: string
  severity: string
  status: string
  source?: string | null
  source_ip?: string | null
  username?: string | null
  reason?: string | null
  created_at?: string | null
}

export type ApiEvent = {
  timestamp: string
  source: string
  event_type: string
  username?: string | null
  source_ip?: string | null
  hostname?: string | null
  severity: string
  message: string
}

// Calls the backend with the login token. Throws an Error whose message is readable.
export async function api<T>(
  token: string,
  path: string,
  options: { method?: string; body?: unknown } = {}
): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    method: options.method ?? 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      ...(options.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  })

  if (!response.ok) {
    let detail = ''
    try {
      const data = await response.json()
      detail = typeof data.detail === 'string' ? data.detail : ''
    } catch {
      // no JSON body
    }
    if (response.status === 401) {
      throw new Error('Your session expired. Log out and log in again.')
    }
    throw new Error(detail || `Request failed (HTTP ${response.status})`)
  }

  return (await response.json()) as T
}

export function fetchAlerts(token: string) {
  return api<ApiAlert[]>(token, '/alerts?limit=200')
}

export function formatSeverity(value: string): 'Critical' | 'High' | 'Medium' | 'Low' {
  const severity = value.toLowerCase()
  if (severity === 'critical') return 'Critical'
  if (severity === 'high') return 'High'
  if (severity === 'medium') return 'Medium'
  return 'Low'
}

export function formatStatus(value: string): string {
  if (!value || value.toLowerCase() === 'new') return 'Open'
  return value.charAt(0).toUpperCase() + value.slice(1)
}
