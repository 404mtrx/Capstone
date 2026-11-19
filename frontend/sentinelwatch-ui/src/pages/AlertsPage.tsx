import { useEffect, useState } from 'react'
import { Search, AlertTriangle, Eye } from 'lucide-react'
import './AlertsPage.css'
import { api, fetchAlerts, formatSeverity, formatStatus } from '../api'

type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

type Alert = {
  id: string
  title: string
  severity: Severity
  device: string
  time: string
  description: string
  status: string
  rawStatus: string
}

// Which status each alert may move to next (the backend enforces the same rules).
const NEXT_STATUS: Record<string, [string, string][]> = {
  new: [['investigating', 'Start investigating'], ['closed', 'Close alert']],
  investigating: [['escalated', 'Escalate'], ['closed', 'Close alert']],
  escalated: [['investigating', 'Back to investigating'], ['closed', 'Close alert']],
  closed: [['investigating', 'Reopen']],
}

function AlertsPage({ token }: { token: string }) {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('All')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Alert | null>(null)
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)

  const [refresh, setRefresh] = useState(0)

  // Load now, then every 5 seconds so new alerts appear on their own.
  // Calling reload() (after a change) loads again straight away.
  useEffect(() => {
    async function load() {
      try {
        const data = await fetchAlerts(token)

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
            rawStatus: alert.status,
          }))
        )
        setError('')
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Could not load alerts.')
      } finally {
        setLoading(false)
      }
    }

    void load()
    const timer = setInterval(() => void load(), 5000)
    return () => clearInterval(timer)
  }, [token, refresh])

  function reload() {
    setRefresh(count => count + 1)
  }

  const filteredAlerts = alerts.filter(alert => {
    const matchesSeverity = filter === 'All' || alert.severity === filter
    const matchesSearch =
      `${alert.title} ${alert.device} ${alert.id}`
        .toLowerCase()
        .includes(search.toLowerCase())

    return matchesSeverity && matchesSearch
  })

  async function changeStatus(alert: Alert, status: string) {
    setBusy(true)
    try {
      await api(token, `/alerts/${alert.id}`, { method: 'PATCH', body: { status } })
      setNotice(`Alert ${alert.id} is now ${status}.`)
      setSelected(null)
      reload()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : 'Could not update the alert.')
    } finally {
      setBusy(false)
    }
  }

  async function openCase(alert: Alert) {
    setBusy(true)
    try {
      const created = await api<{ id: number }>(token, '/cases', {
        method: 'POST',
        body: { alert_id: Number(alert.id), title: `${alert.title} - ${alert.device}` },
      })
      setNotice(`Case ${created.id} opened for alert ${alert.id}.`)
      setSelected(null)
      reload()
    } catch (err) {
      setNotice(err instanceof Error ? err.message : 'Could not open a case.')
    } finally {
      setBusy(false)
    }
  }

  function statusClass(alert: Alert) {
    return alert.rawStatus === 'closed' ? 'status-reviewed' : 'status-open'
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

      {notice && (
        <p className="alerts-notice" role="status">
          {notice}
        </p>
      )}

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
                    className={statusClass(alert)}
                  >
                    {alert.status}
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
              <dt>Status</dt><dd>{selected.status}</dd>
            </dl>

            <div className="alert-detail-actions">
              <button onClick={() => setSelected(null)}>Close</button>
              {selected.rawStatus !== 'closed' && (
                <button disabled={busy} onClick={() => void openCase(selected)}>
                  Open case
                </button>
              )}
              {(NEXT_STATUS[selected.rawStatus] ?? []).map(([status, label]) => (
                <button
                  key={status}
                  disabled={busy}
                  onClick={() => void changeStatus(selected, status)}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </section>
  )
}

export default AlertsPage