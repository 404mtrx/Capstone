
import { useState } from 'react'
import { Search, FileText } from 'lucide-react'
import './LogsPage.css'

type LogLevel = 'Info' | 'Warning' | 'Error'

type SecurityLog = {
  id: string
  timestamp: string
  source: string
  event: string
  level: LogLevel
  ipAddress: string
}

const sampleLogs: SecurityLog[] = [
  {
    id: 'LOG-001',
    timestamp: '2026-10-12 10:42:15',
    source: 'SERVER-01',
    event: 'Failed login attempt',
    level: 'Warning',
    ipAddress: '192.168.1.105'
  },
  {
    id: 'LOG-002',
    timestamp: '2026-10-12 10:25:30',
    source: 'PC-ADMIN',
    event: 'Administrator login successful',
    level: 'Info',
    ipAddress: '192.168.1.110'
  },
  {
    id: 'LOG-003',
    timestamp: '2026-10-12 09:30:45',
    source: 'PC-004',
    event: 'Multiple authentication failures',
    level: 'Error',
    ipAddress: '192.168.1.120'
  },
  {
    id: 'LOG-004',
    timestamp: '2026-10-12 08:15:00',
    source: 'PC-007',
    event: 'User login outside business hours',
    level: 'Warning',
    ipAddress: '192.168.1.130'
  },
  {
    id: 'LOG-005',
    timestamp: '2026-10-12 07:55:10',
    source: 'SERVER-02',
    event: 'System service started',
    level: 'Info',
    ipAddress: '192.168.1.140'
  }
]

function LogsPage() {
  const [search, setSearch] = useState('')
  const [level, setLevel] = useState('All')

  const filteredLogs = sampleLogs.filter(log => {
    const matchesLevel = level === 'All' || log.level === level
    const matchesSearch =
      `${log.id} ${log.source} ${log.event} ${log.ipAddress}`
        .toLowerCase()
        .includes(search.toLowerCase())

    return matchesLevel && matchesSearch
  })

  return (
    <section className="logs-page">
      <div className="logs-heading">
        <div>
          <h2>Security Logs</h2>
          <p>Monitor events collected from your connected systems.</p>
        </div>
        <FileText size={28} />
      </div>

      <div className="logs-toolbar">
        <div className="logs-search">
          <Search size={18} />
          <input
            type="search"
            placeholder="Search logs, devices, or IP addresses..."
            value={search}
            onChange={event => setSearch(event.target.value)}
          />
        </div>

        <select
          aria-label="Filter logs by level"
          value={level}
          onChange={event => setLevel(event.target.value)}
        >
          <option value="All">All Levels</option>
          <option value="Info">Info</option>
          <option value="Warning">Warning</option>
          <option value="Error">Error</option>
        </select>
      </div>

      <div className="logs-table-wrapper">
        <table className="security-logs-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source</th>
              <th>Event</th>
              <th>Level</th>
              <th>IP Address</th>
            </tr>
          </thead>

          <tbody>
            {filteredLogs.map(log => (
              <tr key={log.id}>
                <td>{log.timestamp}</td>
                <td><strong>{log.source}</strong></td>
                <td>{log.event}</td>
                <td>
                  <span className={`log-level ${log.level.toLowerCase()}`}>
                    {log.level}
                  </span>
                </td>
                <td>{log.ipAddress}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {filteredLogs.length === 0 && (
          <p className="logs-empty">No matching logs found.</p>
        )}
      </div>

      <p className="logs-footer">
        Showing {filteredLogs.length} of {sampleLogs.length} sample log events
      </p>
    </section>
  )
}

export default LogsPage
