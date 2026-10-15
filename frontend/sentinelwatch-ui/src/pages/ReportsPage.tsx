
import { useState } from 'react'
import {
  Download,
  ShieldAlert,
  Monitor,
  CheckCircle,
  Activity,
} from 'lucide-react'
import './ReportsPage.css'

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

const reports: Record<Period, Report> = {
  '7': {
    total: 27,
    critical: 2,
    high: 5,
    medium: 8,
    low: 12,
    devices: 5,
    reviewed: 18,
  },
  '30': {
    total: 94,
    critical: 8,
    high: 20,
    medium: 31,
    low: 35,
    devices: 5,
    reviewed: 73,
  },
  '90': {
    total: 268,
    critical: 19,
    high: 54,
    medium: 91,
    low: 104,
    devices: 5,
    reviewed: 221,
  },
}

const events = [
  {
    id: 'EVT-001',
    event: 'Multiple failed login attempts',
    source: 'SERVER-01',
    severity: 'Critical',
  },
  {
    id: 'EVT-002',
    event: 'Suspicious administrator login',
    source: 'PC-ADMIN',
    severity: 'High',
  },
  {
    id: 'EVT-003',
    event: 'Unusual network connection',
    source: 'PC-004',
    severity: 'Medium',
  },
  {
    id: 'EVT-004',
    event: 'System configuration change',
    source: 'SERVER-02',
    severity: 'Low',
  },
]

function ReportsPage() {
  const [period, setPeriod] = useState<Period>('7')
  const report = reports[period]

  const severities = [
    { name: 'Critical', count: report.critical, type: 'critical' },
    { name: 'High', count: report.high, type: 'high' },
    { name: 'Medium', count: report.medium, type: 'medium' },
    { name: 'Low', count: report.low, type: 'low' },
  ]

  function exportCSV() {
    const rows = [
      ['SentinelWatch Demo Security Report'],
      ['Reporting Period', `Last ${period} days`],
      [],
      ['Metric', 'Count'],
      ['Total Alerts', report.total],
      ['Critical Alerts', report.critical],
      ['High Alerts', report.high],
      ['Medium Alerts', report.medium],
      ['Low Alerts', report.low],
      ['Monitored Devices', report.devices],
      ['Reviewed Alerts', report.reviewed],
      [],
      ['Recent Demo Event', 'Source', 'Severity'],
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
    link.download = `sentinelwatch-demo-${period}-days.csv`
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
          <span>Monitored Devices</span>
          <strong>{report.devices}</strong>
        </div>

        <div className="report-stat-card">
          <CheckCircle size={24} />
          <span>Reviewed Alerts</span>
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
        <p>Illustrative events for the frontend demonstration.</p>

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

      <p className="reports-disclaimer">
        Sample Data — Reports are for demonstration only.
        They do not represent live security monitoring.
      </p>
    </section>
  )
}

export default ReportsPage
