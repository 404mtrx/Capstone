import { useEffect, useState } from 'react'
import { Monitor, Search } from 'lucide-react'
import { api, type ApiEvent } from '../api'
import './DevicesPage.css'

type ObservedHost = { name: string; latest: number | null; count: number }

export default function DevicesPage({ token }: { token: string }) {
  const [events, setEvents] = useState<ApiEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [refresh, setRefresh] = useState(0)
  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError('')
    setEvents([])
    async function load() {
      try {
        const data: unknown = await api<unknown>(token, '/events?size=500')
        if (!Array.isArray(data) || !data.every(event => event && typeof event.timestamp === 'string')) throw new Error('Unexpected events response.')
        if (!cancelled) setEvents(data)
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Could not load observed hosts.')
      } finally { if (!cancelled) setLoading(false) }
    }
    void load()
    return () => { cancelled = true }
  }, [token, refresh])
  const hosts = new Map<string, ObservedHost>()
  for (const event of events) {
    const name = event.hostname?.trim()
    // Remote source IPs can belong to attackers, so do not treat them as managed devices.
    if (!name) continue
    const time = Date.parse(event.timestamp)
    const previous = hosts.get(name)
    hosts.set(name, { name, count: (previous?.count || 0) + 1,
      latest: Number.isFinite(time) ? Math.max(previous?.latest ?? -Infinity, time) : previous?.latest ?? null })
  }
  const all = Array.from(hosts.values()).sort((a, b) => a.name.localeCompare(b.name))
  const filtered = all.filter(host => host.name.toLowerCase().includes(search.trim().toLowerCase()))
  const unassociated = events.filter(event => !event.hostname?.trim()).length
  return <section className="devices-page">
    <div className="devices-heading"><div><h2>Hosts Observed in Logs</h2><p>Hostnames found in up to 500 returned events. This is not a complete managed-device inventory.</p></div><Monitor size={28}/></div>
    <div className="devices-summary"><div className="device-summary-card"><span>Observed hostnames</span><strong>{loading || error ? '—' : all.length}</strong></div><div className="device-summary-card"><span>Events in this view</span><strong>{loading || error ? '—' : events.length}</strong></div><div className="device-summary-card"><span>Connection status</span><strong>Unknown</strong></div></div>
    <p>Online/offline state, device type, and host IP are unavailable from this data. Event source IPs may identify remote clients rather than the host.</p>
    <div className="devices-toolbar"><div className="devices-search"><Search size={18}/><input type="search" aria-label="Search observed hostnames" placeholder="Search hostnames…" value={search} onChange={event => setSearch(event.target.value)}/></div><button type="button" disabled={loading} onClick={() => setRefresh(value => value + 1)}>{loading ? 'Loading…' : 'Refresh hosts'}</button></div>
    {error && <p role="alert">{error}</p>}
    {loading && <p role="status">Loading observed hosts…</p>}
    {!loading && !error && <><div className="devices-table-wrapper"><table className="security-devices-table"><thead><tr><th>Hostname</th><th>Connection</th><th>Latest event time</th><th>Events in this view</th></tr></thead><tbody>{filtered.map(host => <tr key={host.name}><td><strong>{host.name}</strong></td><td>Unknown</td><td>{host.latest === null ? 'Unknown' : new Date(host.latest).toLocaleString()}</td><td>{host.count}</td></tr>)}</tbody></table>{filtered.length === 0 && <p className="devices-empty">{all.length ? 'No matching hostnames.' : 'No hostnames found in returned events.'}</p>}</div><p className="devices-footer">Showing {filtered.length} of {all.length} observed hostnames. {unassociated} returned events have no hostname. Counts apply only to this event sample.</p></>}
  </section>
}
