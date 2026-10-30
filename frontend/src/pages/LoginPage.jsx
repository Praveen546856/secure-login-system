import { useState } from 'react'
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { useNotify } from '../context/NotificationContext'
import { describeError } from '../services/api'
import { validateEmail } from '../validation'
import PasswordField from '../components/PasswordField'
import TextField from '../components/TextField'
import Spinner from '../components/Spinner'

export default function LoginPage() {
  const { user, login, loginTwoFactor } = useAuth()
  const notify = useNotify()
  const navigate = useNavigate()
  const location = useLocation()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [errors, setErrors] = useState({})
  const [challenge, setChallenge] = useState(null)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)

  if (user) return <Navigate to="/dashboard" replace />

  async function submitCredentials(e) {
    e.preventDefault()
    const found = {}
    const emailError = validateEmail(email)
    if (emailError) found.email = emailError
    if (!password) found.password = 'Enter your password.'
    setErrors(found)
    if (Object.keys(found).length) return

    setBusy(true)
    try {
      const result = await login(email.trim(), password)
      if (result.twoFactorChallenge) {
        setChallenge(result.twoFactorChallenge)
        setPassword('') // the password is no longer needed in memory
      } else {
        notify.success('Welcome back!')
        navigate(location.state?.from || '/dashboard', { replace: true })
      }
    } catch (err) {
      notify.error(describeError(err).message)
    } finally {
      setBusy(false)
    }
  }

  async function submitCode(e) {
    e.preventDefault()
    setBusy(true)
    try {
      await loginTwoFactor(challenge, code.trim())
      notify.success('Welcome back!')
      navigate(location.state?.from || '/dashboard', { replace: true })
    } catch (err) {
      const message = describeError(err).message
      notify.error(message)
      if (/expired/i.test(message)) { setChallenge(null); setCode('') }
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="auth-page">
      <div className="card auth-card">
        <h1>Log in</h1>
        {!challenge ? (
          <form onSubmit={submitCredentials} noValidate>
            <TextField id="login-email" label="Email" type="email" value={email} autoComplete="username"
              onChange={(e) => setEmail(e.target.value)} error={errors.email} />
            <PasswordField id="login-password" label="Password" value={password} onChange={setPassword}
              autoComplete="current-password" error={errors.password} />
            <button type="submit" className="btn primary wide" disabled={busy}>
              {busy ? <Spinner label="Logging in" /> : 'Log in'}
            </button>
            <p className="hint center-text">No account? <Link to="/register">Create one</Link></p>
          </form>
        ) : (
          <form onSubmit={submitCode}>
            <p>Enter the 6-digit code from your authenticator app, or a recovery code.</p>
            <TextField id="login-code" label="Verification code" value={code} autoComplete="one-time-code"
              maxLength={40} autoFocus onChange={(e) => setCode(e.target.value)} />
            <button type="submit" className="btn primary wide" disabled={busy || code.trim().length < 6}>
              {busy ? <Spinner label="Verifying" /> : 'Verify'}
            </button>
            <button type="button" className="btn wide" onClick={() => { setChallenge(null); setCode('') }}>Back</button>
          </form>
        )}
      </div>
    </main>
  )
}
