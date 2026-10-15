
import { useState, type FormEvent } from 'react'
import { Radar, Mail, Lock, Eye, EyeOff } from 'lucide-react'
import './LoginPage.css'

type LoginPageProps = {
  onLogin: () => void
}

function LoginPage({ onLogin }: LoginPageProps) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')

  function handleLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')

    // Frontend demonstration only.
    // Real authentication will be handled by the backend.
    if (
      email.trim().toLowerCase() === 'demo@sentinelwatch.com' &&
      password === 'Demo123!'
    ) {
      onLogin()
    } else {
      setError('Invalid demo email or password.')
    }
  }

  return (
    <div className="login-page">
      <div className="login-container">

        <div className="login-brand">
          <div className="login-brand-icon">
            <Radar size={32} />
          </div>
          <h1>SentinelWatch</h1>
          <p>Small Business Security</p>
        </div>

        <div className="login-card">
          <h2>Welcome Back</h2>
          <p className="login-subtitle">
            Sign in to your security workspace
          </p>

          <form onSubmit={handleLogin}>
            <label htmlFor="login-email">Email Address</label>
            <div className="login-input-wrapper">
              <Mail size={18} />
              <input
                id="login-email"
                type="email"
                placeholder="Enter your email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
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
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
                required
              />

              <button
                type="button"
                className="login-password-toggle"
                onClick={() => setShowPassword(!showPassword)}
                aria-label={
                  showPassword ? 'Hide password' : 'Show password'
                }
              >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>

            {error && (
              <p className="login-error" role="alert">
                {error}
              </p>
            )}

            <button type="submit" className="login-submit">
              Sign In
            </button>
          </form>

          <div className="login-demo-info">
            <strong>Demo Credentials</strong>
            <p>Email: demo@sentinelwatch.com</p>
            <p>Password: Demo123!</p>
          </div>
        </div>

        <p className="login-footer">
          Demo login only — real authentication not connected
        </p>
      </div>
    </div>
  )
}

export default LoginPage
