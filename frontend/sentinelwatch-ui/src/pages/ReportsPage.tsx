
import { useEffect, useState } from 'react'
import {
  Download,
  ShieldAlert,
  Monitor,
  CheckCircle,
  Activity,
} from 'lucide-react'
import './ReportsPage.css'
import { fetchAlerts, formatSeverity, type ApiAlert } from '../api'

type Period = '7' | '30' | '90'

type Report = {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  devices: number
  reviewed: number
}

function buildReport(alerts: ApiAlert[], period: Period): Report {
  const since = Date.now() - Number(period) * 24 * 60 * 60 * 1000
  const inPeriod = alerts.filter(
    alert => !alert.created_at || new Date(alert.created_at).getTime() >= since
  )
  const count = (level: string) =>
    inPeriod.filter(alert => formatSeverity(alert.severity) === level).length
  const devices = new Set(
    inPeriod.map(alert => alert.source_ip || alert.source || alert.username).filter(Boolean)
  )

  return {
    total: inPeriod.length,
    critical: count('Critical'),
    high: count('High'),
    medium: count('Medium'),
    low: count('Low'),
    devices: devices.size,
    reviewed: inPeriod.filter(alert => alert.status !== 'new').length,
  }
}

function ReportsPage({ token }: { token: string }) {
  const [period, setPeriod] = useState<Period>('7')
  const [alerts, setAlerts] = useState<ApiAlert[]>([])
  const [error, setError] = useState('')

  useEffect(() => {
    async function load() {
      try {
        setAlerts(await fetchAlerts(token))
        setError('')
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Could not load alerts.')
      }
    }
    void load()
    const timer = setInterval(() => void load(), 10000)
    return () => clearInterval(timer)
  }, [token])

  const report = buildReport(alerts, period)
  const events = alerts.slice(0, 5).map(alert => ({
    id: String(alert.id),
    event: alert.rule_name,
    source: alert.source_ip || alert.source || alert.username || 'Unknown',
    severity: formatSeverity(alert.severity),
  }))

  const severities = [
    { name: 'Critical', count: report.critical, type: 'critical' },
    { name: 'High', count: report.high, type: 'high' },
    { name: 'Medium', count: report.medium, type: 'medium' },
    { name: 'Low', count: report.low, type: 'low' },
  ]

  function exportCSV() {
    const rows = [
      ['SentinelWatch Security Report'],
      ['Reporting Period', `Last ${period} days`],
      [],
      ['Metric', 'Count'],
      ['Total Alerts', report.total],
      ['Critical Alerts', report.critical],
      ['High Alerts', report.high],
      ['Medium Alerts', report.medium],
      ['Low Alerts', report.low],
      ['Distinct sources', report.devices],
      ['Alerts past Open', report.reviewed],
      [],
      ['Recent Alert', 'Source', 'Severity'],
      ...events.map(item => [
        item.event,
        item.source,
        item.severity,
      ]),
    ]

    const csv = rows
      .map(row =>
        row.map(value => {
          const text = String(value ?? '')
          return `"${text.replace(/"/g, '""')}"`
        }).join(',')
      )
      .join('\r\n')

    const blob = new Blob([csv], {
      type: 'text/csv;charset=utf-8;',
    })

    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `sentinelwatch-report-${period}-days.csv`
    document.body.appendChild(link)
    link.click()
    link.remove()

    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  return (
    <section className="reports-page">
      <div className="reports-heading">
        <div>
          <h2>Security Reports</h2>
          <p>
            Review security activity and generate summary reports.
          </p>
        </div>

        <button
          type="button"
          className="reports-export"
          onClick={exportCSV}
        >
          <Download size={18} />
          Export CSV
        </button>
      </div>

      <div className="reports-filter">
        <label htmlFor="reports-period">Reporting Period</label>
        <select
          id="reports-period"
          value={period}
          onChange={event =>
            setPeriod(event.target.value as Period)
          }
        >
          <option value="7">Last 7 Days</option>
          <option value="30">Last 30 Days</option>
          <option value="90">Last 90 Days</option>
        </select>
      </div>

      <div className="reports-summary">
        <div className="report-stat-card">
          <ShieldAlert size={24} />
          <span>Total Alerts</span>
          <strong>{report.total}</strong>
        </div>

        <div className="report-stat-card">
          <Activity size={24} />
          <span>Critical Alerts</span>
          <strong>{report.critical}</strong>
        </div>

        <div className="report-stat-card">
          <Monitor size={24} />
          <span>Distinct Sources</span>
          <strong>{report.devices}</strong>
        </div>

        <div className="report-stat-card">
          <CheckCircle size={24} />
          <span>Alerts Past Open</span>
          <strong>{report.reviewed}</strong>
        </div>
      </div>

      <div className="reports-panel">
        <h3>Alert Severity Breakdown</h3>
        <p>Distribution of alerts for the selected reporting period.</p>

        <div className="severity-chart">
          {severities.map(item => (
            <div className="severity-chart-row" key={item.name}>
              <span>{item.name}</span>

              <div className="severity-track">
                <div
                  className={`severity-fill ${item.type}`}
                  style={{
                    width: `${
                      report.total
                        ? (item.count / report.total) * 100
                        : 0
                    }%`,
                  }}
                />
              </div>

              <strong>{item.count}</strong>
            </div>
          ))}
        </div>
      </div>

      <div className="reports-panel">
        <h3>Recent Security Events</h3>
        <p>The five newest alerts from the detection engine.</p>

        <div className="reports-table-wrapper">
          <table className="reports-table">
            <thead>
              <tr>
                <th>Event</th>
                <th>Source</th>
                <th>Severity</th>
              </tr>
            </thead>

            <tbody>
              {events.map(item => (
                <tr key={item.id}>
                  <td>{item.event}</td>
                  <td>{item.source}</td>
                  <td>
                    <span
                      className={`report-severity ${item.severity.toLowerCase()}`}
                    >
                      {item.severity}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {error && <p className="reports-disclaimer">{error}</p>}
      <p className="reports-disclaimer">
        Live data from the SentinelWatch API (refreshes every 10 seconds).
      </p>
    </section>
  )
}

export default ReportsPage
