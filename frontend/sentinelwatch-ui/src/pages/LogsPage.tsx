
import { useEffect, useState } from 'react'
import { Search, FileText } from 'lucide-react'
import './LogsPage.css'
import { api, type ApiEvent } from '../api'

type LogLevel = 'Info' | 'Warning' | 'Error'

type SecurityLog = {
  id: string
  timestamp: string
  source: string
  event: string
  level: LogLevel
  ipAddress: string
}

function toLog(event: ApiEvent, index: number): SecurityLog {
  const severity = event.severity.toLowerCase()
  return {
    id: `${event.timestamp}-${index}`,
    timestamp: new Date(event.timestamp).toLocaleString(),
    source: event.hostname || event.source,
    event: `${event.event_type.replace(/_/g, ' ')}${event.username ? ` (${event.username})` : ''}`,
    level: severity === 'high' || severity === 'critical' ? 'Error' : severity === 'medium' ? 'Warning' : 'Info',
    ipAddress: event.source_ip || '-',
  }
}

function LogsPage({ token }: { token: string }) {
  const [search, setSearch] = useState('')
  const [level, setLevel] = useState('All')
  const [logs, setLogs] = useState<SecurityLog[]>([])
  const [error, setError] = useState('')

  // Newest events from OpenSearch, refreshed every 10 seconds.
  useEffect(() => {
    async function load() {
      try {
        const events = await api<ApiEvent[]>(token, '/events?size=200')
        setLogs(events.map(toLog))
        setError('')
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Could not load events.')
      }
    }
    void load()
    const timer = setInterval(() => void load(), 10000)
    return () => clearInterval(timer)
  }, [token])

  const filteredLogs = logs.filter(log => {
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

        {error && <p className="logs-empty">{error}</p>}
        {!error && filteredLogs.length === 0 && (
          <p className="logs-empty">
            {logs.length === 0 ? 'No events collected yet.' : 'No matching logs found.'}
          </p>
        )}
      </div>

      <p className="logs-footer">
        Showing {filteredLogs.length} of {logs.length} recent collected events
      </p>
    </section>
  )
}

export default LogsPage
