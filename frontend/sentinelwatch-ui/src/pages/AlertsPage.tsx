import { useEffect, useState } from 'react'
import { Search, AlertTriangle, Eye } from 'lucide-react'
import './AlertsPage.css'
import { API_URL } from '../config'

type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

type Alert = {
  id: string
  title: string
  severity: Severity
  device: string
  time: string
  description: string
  status: string
}

type ApiAlert = {
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

function formatSeverity(value: string): Severity {
  const severity = value.toLowerCase()

  if (severity === 'critical') return 'Critical'
  if (severity === 'high') return 'High'
  if (severity === 'medium') return 'Medium'
  return 'Low'
}

function formatStatus(value: string): string {
  if (!value || value.toLowerCase() === 'new') return 'Open'
  return value.charAt(0).toUpperCase() + value.slice(1)
}

function AlertsPage({ token }: { token: string }) {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('All')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Alert | null>(null)
  const [reviewed, setReviewed] = useState<string[]>([])

  useEffect(() => {
    async function loadAlerts() {
      try {
        const response = await fetch(`${API_URL}/alerts`, {
  headers: {
    Authorization: `Bearer ${token}`,
  },
})

        if (!response.ok) {
          throw new Error(`Could not load alerts (HTTP ${response.status})`)
        }

        const data: ApiAlert[] = await response.json()

        setAlerts(
          data.map(alert => ({
            id: String(alert.id),
            title: alert.rule_name,
            severity: formatSeverity(alert.severity),
            device: alert.source_ip || alert.source || alert.username || 'Unknown',
            time: alert.created_at
              ? new Date(alert.created_at).toLocaleString()
              : 'Unknown time',
            description: alert.reason || 'No description provided.',
            status: formatStatus(alert.status),
          }))
        )
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Could not load alerts.')
      } finally {
        setLoading(false)
      }
    }

    void loadAlerts()
  }, [])

  const filteredAlerts = alerts.filter(alert => {
    const matchesSeverity = filter === 'All' || alert.severity === filter
    const matchesSearch =
      `${alert.title} ${alert.device} ${alert.id}`
        .toLowerCase()
        .includes(search.toLowerCase())

    return matchesSeverity && matchesSearch
  })

  function toggleReviewed(id: string) {
    setReviewed(previous =>
      previous.includes(id)
        ? previous.filter(item => item !== id)
        : [...previous, id]
    )
  }

  function currentStatus(alert: Alert) {
    return reviewed.includes(alert.id) ? 'Reviewed' : alert.status
  }

  return (
    <section className="alerts-page">
      <div className="alerts-page-heading">
        <div>
          <h2>Security Alerts</h2>
          <p>Review and manage detected security threats.</p>
        </div>
      </div>

      <div className="alerts-toolbar">
        <div className="alerts-search">
          <Search size={18} />
          <input
            type="search"
            placeholder="Search alerts or devices..."
            value={search}
            onChange={event => setSearch(event.target.value)}
          />
        </div>

        <select
          aria-label="Filter alerts by severity"
          value={filter}
          onChange={event => setFilter(event.target.value)}
        >
          {['All', 'Critical', 'High', 'Medium', 'Low'].map(level => (
            <option key={level} value={level}>
              {level === 'All' ? 'All Severities' : level}
            </option>
          ))}
        </select>
      </div>

      <div className="alerts-table-wrapper">
        <table className="security-alerts-table">
          <thead>
            <tr>
              <th>Alert</th>
              <th>Severity</th>
              <th>Device</th>
              <th>Time</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>

          <tbody>
            {filteredAlerts.map(alert => (
              <tr key={alert.id}>
                <td>
                  <strong>{alert.title}</strong>
                  <small>{alert.id}</small>
                </td>
                <td>
                  <span className={`alert-severity ${alert.severity.toLowerCase()}`}>
                    {alert.severity}
                  </span>
                </td>
                <td>{alert.device}</td>
                <td>{alert.time}</td>
                <td>
                  <span
                    className={
                      currentStatus(alert) === 'Reviewed'
                        ? 'status-reviewed'
                        : 'status-open'
                    }
                  >
                    {currentStatus(alert)}
                  </span>
                </td>
                <td>
                  <button
                    className="alert-review-button"
                    onClick={() => setSelected(alert)}
                  >
                    <Eye size={16} /> Review
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {loading && <p className="alerts-empty">Loading alerts…</p>}
        {error && <p className="alerts-empty">{error}</p>}
        {!loading && !error && filteredAlerts.length === 0 && (
          <p className="alerts-empty">
            {alerts.length === 0
              ? 'The backend returned no alerts yet.'
              : 'No matching alerts found.'}
          </p>
        )}
      </div>

      {selected && (
        <div className="alert-detail-overlay" onClick={() => setSelected(null)}>
          <div
            className="alert-detail-card"
            role="dialog"
            aria-modal="true"
            aria-label="Alert details"
            onClick={event => event.stopPropagation()}
          >
            <div className="alert-detail-header">
              <AlertTriangle size={24} />
              <h2>Alert Details</h2>
            </div>

            <h3>{selected.title}</h3>
            <p>{selected.description}</p>

            <dl>
              <dt>Severity</dt><dd>{selected.severity}</dd>
              <dt>Device / source</dt><dd>{selected.device}</dd>
              <dt>Time</dt><dd>{selected.time}</dd>
              <dt>Status</dt><dd>{currentStatus(selected)}</dd>
            </dl>

            <div className="alert-detail-actions">
              <button onClick={() => setSelected(null)}>Close</button>
              <button
                onClick={() => {
                  toggleReviewed(selected.id)
                  setSelected(null)
                }}
              >
                {reviewed.includes(selected.id)
                  ? 'Mark as Open'
                  : 'Mark as Reviewed'}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}

export default AlertsPage