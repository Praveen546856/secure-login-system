import { useState } from 'react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { useNotify } from '../context/NotificationContext'
import { register } from '../services/authService'
import { describeError } from '../services/api'
import { validateEmail, validatePassword, validateUsername } from '../validation'
import PasswordField from '../components/PasswordField'
import PasswordStrength from '../components/PasswordStrength'
import TextField from '../components/TextField'
import Spinner from '../components/Spinner'

export default function RegisterPage() {
  const { user } = useAuth()
  const notify = useNotify()
  const navigate = useNavigate()
  const [form, setForm] = useState({ username: '', email: '', password: '', confirm: '' })
  const [errors, setErrors] = useState({})
  const [busy, setBusy] = useState(false)

  if (user) return <Navigate to="/dashboard" replace />

  const set = (key) => (value) => setForm((f) => ({ ...f, [key]: value }))

  async function submit(e) {
    e.preventDefault()
    const found = {}
    const u = validateUsername(form.username); if (u) found.username = u
    const m = validateEmail(form.email); if (m) found.email = m
    const p = validatePassword(form.password, form.username, form.email); if (p) found.password = p
    if (form.password !== form.confirm) found.confirm = 'Passwords do not match.'
    setErrors(found)
    if (Object.keys(found).length) return

    setBusy(true)
    try {
      await register({ username: form.username, email: form.email.trim(), password: form.password })
      notify.success('Account created. Please log in.')
      navigate('/login', { replace: true })
    } catch (err) {
      const { message, fields } = describeError(err)
      setErrors(fields)
      notify.error(message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="auth-page">
      <div className="card auth-card">
        <h1>Create account</h1>
        <form onSubmit={submit} noValidate>
          <TextField id="reg-username" label="Username" value={form.username} autoComplete="username"
            onChange={(e) => set('username')(e.target.value)} error={errors.username} />
          <TextField id="reg-email" label="Email" type="email" value={form.email} autoComplete="email"
            onChange={(e) => set('email')(e.target.value)} error={errors.email} />
          <PasswordField id="reg-password" label="Password" value={form.password} onChange={set('password')}
            autoComplete="new-password" error={errors.password} />
          <PasswordStrength password={form.password} username={form.username} email={form.email} />
          <PasswordField id="reg-confirm" label="Confirm password" value={form.confirm} onChange={set('confirm')}
            autoComplete="new-password" error={errors.confirm} />
          <button type="submit" className="btn primary wide" disabled={busy}>
            {busy ? <Spinner label="Creating account" /> : 'Register'}
          </button>
          <p className="hint center-text">Already registered? <Link to="/login">Log in</Link></p>
        </form>
      </div>
    </main>
  )
}
