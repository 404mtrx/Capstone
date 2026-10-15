
import { useState } from 'react'
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

const threats = [
  { name: 'Critical', count: 2, color: 'critical' },
  { name: 'High', count: 5, color: 'high' },
  { name: 'Medium', count: 8, color: 'medium' },
  { name: 'Low', count: 12, color: 'low' },
]

function App() {
  const [activePage, setActivePage] = useState('Dashboard')
  const [isLoggedIn, setIsLoggedIn] = useState(false)

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
      // Theme still changes if storage is unavailable.
    }
  }

  function handleLogin() {
    setActivePage('Dashboard')
    setIsLoggedIn(true)
  }

  function handleLogout() {
    setIsLoggedIn(false)
    setActivePage('Dashboard')
  }

  // Frontend demonstration only.
  // Real authentication must be handled by the backend.
  if (!isLoggedIn) {
    return <LoginPage onLogin={handleLogin} />
  }

  return (
    <div className={`app-layout theme-${theme}`}>
      {/* Sidebar */}
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
          {menuItems.map((item) => {
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

                <span
                  className={
                    item.name === 'Alerts' ? 'alerts-label' : ''
                  }
                >
                  {item.name}
                </span>

                {item.name === 'Alerts' && (
                  <span className="alerts-counter">7</span>
                )}
              </button>
            )
          })}
        </nav>

        {/* Sidebar Footer and Logout */}
        <div className="sidebar-footer">
          <div className="demo-status">
            <span className="online-dot" />
            <span>Demo Mode</span>
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

      {/* Main Content */}
      <main className="main-content">
        <header className="top-header">
          <div>
            <h1>
              {activePage === 'Dashboard'
                ? 'Security Overview'
                : activePage}
            </h1>

            <p>
              Welcome to your SentinelWatch security workspace.
            </p>
          </div>

          <span className="demo-badge">Sample Data</span>
        </header>

        {activePage === 'Dashboard' ? (
          <>
            {/* Welcome Section */}
            <section className="welcome-card">
              <h2>Your Business Security at a Glance</h2>

              <p>
                Monitor threats, review alerts, and protect your
                business from one simple dashboard.
              </p>
            </section>

            {/* Threat Overview */}
            <section className="threat-grid">
              {threats.map((threat) => (
                <div
                  className={`threat-card ${threat.color}`}
                  key={threat.name}
                >
                  <span>{threat.name} Threats</span>
                  <h2>{threat.count}</h2>
                  <p>Detected security alerts</p>
                </div>
              ))}
            </section>

            {/* Attention Panel */}
            <section className="alerts-panel">
              <h2>Needs Your Attention</h2>

              <p>
                Important security events requiring review
              </p>

              <div className="alert-row">
                <div>
                  <strong>
                    Possible brute-force login attack
                  </strong>

                  <p>
                    SERVER-01 · Multiple failed login attempts
                  </p>
                </div>

                <span className="alert-badge critical-badge">
                  Critical
                </span>
              </div>

              <div className="alert-row">
                <div>
                  <strong>
                    Suspicious administrator login
                  </strong>

                  <p>
                    PC-ADMIN · Unusual login activity
                  </p>
                </div>

                <span className="alert-badge high-badge">
                  High
                </span>
              </div>
            </section>
          </>
        ) : activePage === 'Alerts' ? (
          <AlertsPage />
        ) : activePage === 'Logs' ? (
          <LogsPage />
        ) : activePage === 'Devices' ? (
          <DevicesPage /> 
          ) : activePage === 'Rules' ? (
          <RulesPage /> 
          ) : activePage === 'Reports' ? (
           <ReportsPage />
        ) : activePage === 'Settings' ? (
          <>
            {/* Appearance Settings */}
            <section className="alerts-panel settings-panel">
              <h2>Appearance Settings</h2>

              <p>
                Customize how SentinelWatch looks on your screen.
              </p>

              <div className="theme-setting">
                <div>
                  <h3>Dashboard Theme</h3>
                  <p>Choose your preferred appearance.</p>
                </div>

                <div className="theme-options">
                  <button
                    type="button"
                    className={`theme-option ${
                      theme === 'dark'
                        ? 'theme-option-active'
                        : ''
                    }`}
                    onClick={() => changeTheme('dark')}
                    aria-pressed={theme === 'dark'}
                  >
                    Dark Navy
                  </button>

                  <button
                    type="button"
                    className={`theme-option ${
                      theme === 'light'
                        ? 'theme-option-active'
                        : ''
                    }`}
                    onClick={() => changeTheme('light')}
                    aria-pressed={theme === 'light'}
                  >
                    Clean White
                  </button>
                </div>
              </div>
            </section>

            {/* Account Security */}
            <AccountSecurity />
          </>
        ) : (
          <section className="alerts-panel">
            <h2>{activePage}</h2>

            <p>
              This section will be developed next.
            </p>
          </section>
        )}
      </main>
    </div>
  )
}

export default App
