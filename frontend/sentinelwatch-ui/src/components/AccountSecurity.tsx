
import { useState, type FormEvent } from 'react'
import { LockKeyhole, ShieldCheck, KeyRound } from 'lucide-react'
import './AccountSecurity.css'

function AccountSecurity() {
  const [showPasswordForm, setShowPasswordForm] = useState(false)
  const [mfaInfoOpen, setMfaInfoOpen] = useState(false)
  const [message, setMessage] = useState('')

  function handlePasswordChange(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setMessage(
      'Demo only: Password changes require a secure backend.'
    )
  }

  return (
    <section className="account-security">
      <div className="security-section-heading">
        <ShieldCheck size={24} />
        <div>
          <h2>Account Security</h2>
          <p>Manage your sign-in and account protection.</p>
        </div>
      </div>

      <div className="security-setting-row">
        <div className="security-setting-info">
          <LockKeyhole size={22} />
          <div>
            <h3>Password</h3>
            <p>Update your account password securely.</p>
          </div>
        </div>

        <button
          type="button"
          className="security-action-button"
          onClick={() => {
            setShowPasswordForm(!showPasswordForm)
            setMessage('')
          }}
        >
          {showPasswordForm ? 'Cancel' : 'Change Password'}
        </button>
      </div>

      {showPasswordForm && (
        <form
          className="password-change-form"
          onSubmit={handlePasswordChange}
        >
          <label htmlFor="current-password">Current Password</label>
          <input
            id="current-password"
            type="password"
            autoComplete="current-password"
            placeholder="Current password"
            required
          />

          <label htmlFor="new-password">New Password</label>
          <input
            id="new-password"
            type="password"
            autoComplete="new-password"
            placeholder="New password"
            minLength={12}
            required
          />

          <label htmlFor="confirm-password">Confirm New Password</label>
          <input
            id="confirm-password"
            type="password"
            autoComplete="new-password"
            placeholder="Confirm new password"
            minLength={12}
            required
          />

          <p className="security-helper">
            Use at least 12 characters. This demo does not
            submit or store passwords.
          </p>

          <button type="submit" className="security-primary-button">
            Request Password Change
          </button>
        </form>
      )}

      <div className="security-setting-row">
        <div className="security-setting-info">
          <KeyRound size={22} />
          <div>
            <h3>Two-Factor Authentication (MFA)</h3>
            <p>Add another verification step when signing in.</p>
            <span className="security-status">
              Not configured
            </span>
          </div>
        </div>

        <button
          type="button"
          className="security-action-button"
          onClick={() => setMfaInfoOpen(!mfaInfoOpen)}
        >
          {mfaInfoOpen ? 'Hide Details' : 'Set Up MFA'}
        </button>
      </div>

      {mfaInfoOpen && (
        <div className="mfa-information">
          <h3>Authenticator App</h3>
          <p>
            SentinelWatch will support time-based one-time
            passwords (TOTP), using an authenticator app.
          </p>
          <p>
            MFA enrollment requires backend support for secure
            secret generation, QR-code enrollment, and code
            verification.
          </p>
          <span className="security-status">
            Backend integration required
          </span>
        </div>
      )}

      {message && (
        <p className="security-message" role="status">
          {message}
        </p>
      )}
    </section>
  )
}

export default AccountSecurity
