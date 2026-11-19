import { useEffect, useState } from 'react'
import {
  Radar,
  LayoutDashboard,
  Bell,
  FileText,
  Monitor,
  Settings,
  ShieldAlert,
  BarChart3,
  LogOut,
} from 'lucide-react'

import LoginPage from './pages/LoginPage'
import AlertsPage from './pages/AlertsPage'
import LogsPage from './pages/LogsPage'
import AccountSecurity from './components/AccountSecurity'
import DevicesPage from './pages/DevicesPage'
import RulesPage from './pages/RulesPage'
import ReportsPage from './pages/ReportsPage'

import { fetchAlerts, formatSeverity, type ApiAlert } from './api'

import './App.css'

type Theme = 'dark' | 'light'

const menuItems = [
  { name: 'Dashboard', icon: LayoutDashboard },
  { name: 'Alerts', icon: Bell },
  { name: 'Logs', icon: FileText },
  { name: 'Devices', icon: Monitor },
  { name: 'Rules', icon: ShieldAlert },
  { name: 'Reports', icon: BarChart3 },
  { name: 'Settings', icon: Settings },
]

const LIVE_PAGES = ['Dashboard', 'Alerts', 'Logs', 'Reports']

function App() {
  const [activePage, setActivePage] = useState('Dashboard')
  // The login token is kept for this browser tab only, so a page refresh does not log you out.
  const [accessToken, setAccessToken] = useState<string | null>(() => {
    try {
      return sessionStorage.getItem('sentinelwatch-token')
    } catch {
      return null
    }
  })
  const [liveAlerts, setLiveAlerts] = useState<ApiAlert[]>([])

  // Alert counts for the sidebar and the dashboard, refreshed every 5 seconds.
  useEffect(() => {
    if (!accessToken) return
    const token = accessToken
    async function load() {
      try {
        setLiveAlerts(await fetchAlerts(token))
      } catch {
        // The Alerts page shows the error; keep the last numbers here.
      }
    }
    void load()
    const timer = setInterval(() => void load(), 5000)
    return () => clearInterval(timer)
  }, [accessToken])

  const [theme, setTheme] = useState<Theme>(() => {
    try {
      return localStorage.getItem('sentinelwatch-theme') === 'light'
        ? 'light'
        : 'dark'
    } catch {
      return 'dark'
    }
  })

  function changeTheme(newTheme: Theme) {
    setTheme(newTheme)

    try {
      localStorage.setItem('sentinelwatch-theme', newTheme)
    } catch {
      // The theme still changes if browser storage is unavailable.
    }
  }

  function handleLogin(token: string) {
    try {
      sessionStorage.setItem('sentinelwatch-token', token)
    } catch {
      // Login still works for this page view without storage.
    }
    setAccessToken(token)
    setActivePage('Dashboard')
  }

  function handleLogout() {
    try {
      sessionStorage.removeItem('sentinelwatch-token')
    } catch {
      // nothing to clear
    }
    setAccessToken(null)
    setLiveAlerts([])
    setActivePage('Dashboard')
  }

  if (!accessToken) {
    return <LoginPage onLogin={handleLogin} />
  }

  const openAlerts = liveAlerts.filter(alert => alert.status !== 'closed')
  const threats = ['Critical', 'High', 'Medium', 'Low'].map(name => ({
    name,
    color: name.toLowerCase(),
    count: openAlerts.filter(alert => formatSeverity(alert.severity) === name).length,
  }))
  const attention = openAlerts
    .filter(alert => ['Critical', 'High'].includes(formatSeverity(alert.severity)))
    .slice(0, 5)

  return (
    <div className={`app-layout theme-${theme}`}>
      <aside className="sidebar">
        <div className="logo">
          <div className="sentinel-logo">
            <Radar size={28} strokeWidth={2.4} />
          </div>

          <div>
            <h2>SentinelWatch</h2>
            <span>Small Business Security</span>
          </div>
        </div>

        <p className="menu-label">WORKSPACE</p>

        <nav aria-label="Main navigation">
          {menuItems.map(item => {
            const Icon = item.icon

            return (
              <button
                type="button"
                key={item.name}
                className={`menu-item ${
                  activePage === item.name ? 'selected' : ''
                }`}
                onClick={() => setActivePage(item.name)}
              >
                <Icon size={20} />

                <span className={item.name === 'Alerts' ? 'alerts-label' : ''}>
                  {item.name}
                </span>

                {item.name === 'Alerts' && (
                  <span className="alerts-counter">{openAlerts.length}</span>
                )}
              </button>
            )
          })}
        </nav>

        <div className="sidebar-footer">
          <div className="demo-status">
            <span className="online-dot" />
            <span>Signed In</span>
          </div>

          <button
            type="button"
            className="logout-button"
            onClick={handleLogout}
          >
            <LogOut size={18} />
            <span>Log Out</span>
          </button>
        </div>
      </aside>

      <main className="main-content">
        <header className="top-header">
          <div>
            <h1>
              {activePage === 'Dashboard' ? 'Security Overview' : activePage}
            </h1>
            <p>Welcome to your SentinelWatch security workspace.</p>
          </div>

          <span className="demo-badge">
            {activePage === 'Devices' ? 'Observed Hosts' : activePage === 'Rules' ? 'Rule Catalog' : activePage === 'Settings' ? 'Settings' : LIVE_PAGES.includes(activePage) ? 'Live Data' : 'Sample Data'}
          </span>
        </header>

        {activePage === 'Dashboard' ? (
          <>
            <section className="welcome-card">
              <h2>Your Business Security at a Glance</h2>
              <p>
                Monitor threats, review alerts, and protect your business from
                one simple dashboard.
              </p>
            </section>

            <section className="threat-grid">
              {threats.map(threat => (
                <div
                  className={`threat-card ${threat.color}`}
                  key={threat.name}
                >
                  <span>{threat.name} Threats</span>
                  <h2>{threat.count}</h2>
                  <p>Open security alerts</p>
                </div>
              ))}
            </section>

            <section className="alerts-panel">
              <h2>Needs Your Attention</h2>
              <p>Important security events requiring review</p>

              {attention.length === 0 && (
                <p>No open critical or high alerts right now.</p>
              )}

              {attention.map(alert => {
                const severity = formatSeverity(alert.severity)
                return (
                  <div className="alert-row" key={alert.id}>
                    <div>
                      <strong>{alert.rule_name}</strong>
                      <p>
                        {alert.source_ip || alert.source || alert.username || 'Unknown'}
                        {alert.reason ? ` · ${alert.reason}` : ''}
                      </p>
                    </div>
                    <span className={`alert-badge ${severity.toLowerCase()}-badge`}>
                      {severity}
                    </span>
                  </div>
                )
              })}
            </section>
          </>
        ) : activePage === 'Alerts' ? (
          <AlertsPage token={accessToken} />
        ) : activePage === 'Logs' ? (
          <LogsPage token={accessToken} />
        ) : activePage === 'Devices' ? (
          <DevicesPage token={accessToken} />
        ) : activePage === 'Rules' ? (
          <RulesPage />
        ) : activePage === 'Reports' ? (
          <ReportsPage token={accessToken} />
        ) : activePage === 'Settings' ? (
          <>
            <section className="alerts-panel settings-panel">
              <h2>Appearance Settings</h2>
              <p>Customize how SentinelWatch looks on your screen.</p>

              <div className="theme-setting">
                <div>
                  <h3>Dashboard Theme</h3>
                  <p>Choose your preferred appearance.</p>
                </div>

                <div className="theme-options">
                  <button
                    type="button"
                    className={`theme-option ${
                      theme === 'dark' ? 'theme-option-active' : ''
                    }`}
                    onClick={() => changeTheme('dark')}
                    aria-pressed={theme === 'dark'}
                  >
                    Dark Navy
                  </button>

                  <button
                    type="button"
                    className={`theme-option ${
                      theme === 'light' ? 'theme-option-active' : ''
                    }`}
                    onClick={() => changeTheme('light')}
                    aria-pressed={theme === 'light'}
                  >
                    Clean White
                  </button>
                </div>
              </div>
            </section>

            <AccountSecurity />
          </>
        ) : (
          <section className="alerts-panel">
            <h2>{activePage}</h2>
            <p>This section will be developed next.</p>
          </section>
        )}
      </main>
    </div>
  )
}

export default App