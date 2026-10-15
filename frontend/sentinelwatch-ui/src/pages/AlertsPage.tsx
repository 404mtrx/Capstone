
import { useState } from 'react'
import { Search, AlertTriangle, Eye } from 'lucide-react'
import './AlertsPage.css'

type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

type Alert = {
  id: string
  title: string
  severity: Severity
  device: string
  time: string
  description: string
}

const sampleAlerts: Alert[] = [
  {
    id: 'SW-001',
    title: 'Possible brute-force login attack',
    severity: 'Critical',
    device: 'SERVER-01',
    time: '10:42 AM',
    description: 'Multiple failed login attempts detected.'
  },
  {
    id: 'SW-002',
    title: 'Suspicious administrator login',
    severity: 'High',
    device: 'PC-ADMIN',
    time: '10:25 AM',
    description: 'Administrator login from an unusual location.'
  },
  {
    id: 'SW-003',
    title: 'Multiple failed password attempts',
    severity: 'Medium',
    device: 'PC-004',
    time: '09:30 AM',
    description: 'Repeated authentication failures detected.'
  },
  {
    id: 'SW-004',
    title: 'Login outside business hours',
    severity: 'Low',
    device: 'PC-007',
    time: '08:15 AM',
    description: 'Login detected outside configured business hours.'
  }
]

function AlertsPage() {
  const [filter, setFilter] = useState('All')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Alert | null>(null)
  const [reviewed, setReviewed] = useState<string[]>([])

  const filteredAlerts = sampleAlerts.filter(alert => {
    const matchesSeverity =
      filter === 'All' || alert.severity === filter

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
                  <span className={reviewed.includes(alert.id) ? 'status-reviewed' : 'status-open'}>
                    {reviewed.includes(alert.id) ? 'Reviewed' : 'Open'}
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

        {filteredAlerts.length === 0 && (
          <p className="alerts-empty">No matching alerts found.</p>
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
              <dt>Device</dt><dd>{selected.device}</dd>
              <dt>Time</dt><dd>{selected.time}</dd>
              <dt>Status</dt>
              <dd>{reviewed.includes(selected.id) ? 'Reviewed' : 'Open'}</dd>
            </dl>

            <div className="alert-detail-actions">
              <button onClick={() => setSelected(null)}>
                Close
              </button>
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
