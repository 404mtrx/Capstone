
import { useState } from 'react'
import {
  Monitor,
  Server,
  Search,
  Wifi,
  WifiOff,
} from 'lucide-react'
import './DevicesPage.css'

type DeviceStatus = 'Online' | 'Offline'
type DeviceType = 'Server' | 'Workstation'

type Device = {
  id: string
  name: string
  type: DeviceType
  ipAddress: string
  status: DeviceStatus
  lastSeen: string
  logCount: number
}

const sampleDevices: Device[] = [
  {
    id: 'DEV-001',
    name: 'SERVER-01',
    type: 'Server',
    ipAddress: '192.168.1.105',
    status: 'Online',
    lastSeen: '2 minutes ago',
    logCount: 1250,
  },
  {
    id: 'DEV-002',
    name: 'PC-ADMIN',
    type: 'Workstation',
    ipAddress: '192.168.1.110',
    status: 'Online',
    lastSeen: '5 minutes ago',
    logCount: 845,
  },
  {
    id: 'DEV-003',
    name: 'PC-004',
    type: 'Workstation',
    ipAddress: '192.168.1.120',
    status: 'Online',
    lastSeen: '8 minutes ago',
    logCount: 420,
  },
  {
    id: 'DEV-004',
    name: 'PC-007',
    type: 'Workstation',
    ipAddress: '192.168.1.130',
    status: 'Offline',
    lastSeen: '3 hours ago',
    logCount: 210,
  },
  {
    id: 'DEV-005',
    name: 'SERVER-02',
    type: 'Server',
    ipAddress: '192.168.1.140',
    status: 'Online',
    lastSeen: '1 minute ago',
    logCount: 1680,
  },
]

function DevicesPage() {
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('All')

  const onlineCount = sampleDevices.filter(
    device => device.status === 'Online'
  ).length

  const offlineCount = sampleDevices.length - onlineCount

  const filteredDevices = sampleDevices.filter(device => {
    const matchesStatus =
      statusFilter === 'All' || device.status === statusFilter

    const matchesSearch =
      `${device.name} ${device.type} ${device.ipAddress}`
        .toLowerCase()
        .includes(search.toLowerCase())

    return matchesStatus && matchesSearch
  })

  return (
    <section className="devices-page">
      <div className="devices-heading">
        <div>
          <h2>Monitored Devices</h2>
          <p>
            View the computers and servers connected to SentinelWatch.
          </p>
        </div>
        <Monitor size={28} />
      </div>

      <div className="devices-summary">
        <div className="device-summary-card">
          <span>Total Devices</span>
          <strong>{sampleDevices.length}</strong>
        </div>

        <div className="device-summary-card">
          <span>Online Devices</span>
          <strong className="device-count-online">
            {onlineCount}
          </strong>
        </div>

        <div className="device-summary-card">
          <span>Offline Devices</span>
          <strong className="device-count-offline">
            {offlineCount}
          </strong>
        </div>
      </div>

      <div className="devices-toolbar">
        <div className="devices-search">
          <Search size={18} />
          <input
            type="search"
            placeholder="Search devices or IP addresses..."
            value={search}
            onChange={event => setSearch(event.target.value)}
          />
        </div>

        <select
          aria-label="Filter devices by status"
          value={statusFilter}
          onChange={event => setStatusFilter(event.target.value)}
        >
          <option value="All">All Devices</option>
          <option value="Online">Online</option>
          <option value="Offline">Offline</option>
        </select>
      </div>

      <div className="devices-table-wrapper">
        <table className="security-devices-table">
          <thead>
            <tr>
              <th>Device</th>
              <th>Type</th>
              <th>IP Address</th>
              <th>Status</th>
              <th>Last Seen</th>
              <th>Logs</th>
            </tr>
          </thead>

          <tbody>
            {filteredDevices.map(device => (
              <tr key={device.id}>
                <td>
                  <div className="device-name-cell">
                    {device.type === 'Server' ? (
                      <Server size={18} />
                    ) : (
                      <Monitor size={18} />
                    )}
                    <strong>{device.name}</strong>
                  </div>
                </td>

                <td>{device.type}</td>
                <td>{device.ipAddress}</td>

                <td>
                  <span
                    className={`device-status ${device.status.toLowerCase()}`}
                  >
                    {device.status === 'Online' ? (
                      <Wifi size={14} />
                    ) : (
                      <WifiOff size={14} />
                    )}
                    {device.status}
                  </span>
                </td>

                <td>{device.lastSeen}</td>
                <td>{device.logCount.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {filteredDevices.length === 0 && (
          <p className="devices-empty">
            No matching devices found.
          </p>
        )}
      </div>

      <p className="devices-footer">
        Showing {filteredDevices.length} of {sampleDevices.length} sample devices
      </p>
    </section>
  )
}

export default DevicesPage
