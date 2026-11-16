import { useState, type FormEvent } from 'react'
import { Radar, Mail, Lock, Eye, EyeOff } from 'lucide-react'
import './LoginPage.css'

type LoginPageProps = {
  onLogin: (token: string) => void
}

function LoginPage({ onLogin }: LoginPageProps) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setLoading(true)

    try {
      const response = await fetch('http://127.0.0.1:8000/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
      })

      const data = await response.json()

      if (!response.ok) {
        setError(data.detail || 'Login failed. Check your username and password.')
        return
      }

      onLogin(data.access_token)
    } catch {
      setError('Could not reach the API. Make sure the backend is running.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      <div className="login-container">
        <div className="login-brand">
          <div className="login-brand-icon"><Radar size={32} /></div>
          <h1>SentinelWatch</h1>
          <p>Small Business Security</p>
        </div>

        <div className="login-card">
          <h2>Welcome Back</h2>
          <p className="login-subtitle">Sign in to your security workspace</p>

          <form onSubmit={handleLogin}>
            <label htmlFor="login-username">Username</label>
            <div className="login-input-wrapper">
              <Mail size={18} />
              <input
                id="login-username"
                type="text"
                placeholder="Enter your username"
                value={username}
                onChange={event => setUsername(event.target.value)}
                autoComplete="username"
                required
              />
            </div>

            <label htmlFor="login-password">Password</label>
            <div className="login-input-wrapper">
              <Lock size={18} />
              <input
                id="login-password"
                type={showPassword ? 'text' : 'password'}
                placeholder="Enter your password"
                value={password}
                onChange={event => setPassword(event.target.value)}
                autoComplete="current-password"
                required
              />
              <button
                type="button"
                className="login-password-toggle"
                onClick={() => setShowPassword(value => !value)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>

            {error && <p className="login-error" role="alert">{error}</p>}

            <button type="submit" className="login-submit" disabled={loading}>
              {loading ? 'Signing In…' : 'Sign In'}
            </button>
          </form>
        </div>

        <p className="login-footer">Sign in with your analyst account.</p>
      </div>
    </div>
  )
}

export default LoginPage