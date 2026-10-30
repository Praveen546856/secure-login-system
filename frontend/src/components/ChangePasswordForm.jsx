import { useState } from 'react'
import { changePassword } from '../services/authService'
import { describeError } from '../services/api'
import { useNotify } from '../context/NotificationContext'
import { useAuth } from '../context/AuthContext'
import { validatePassword } from '../validation'
import PasswordField from './PasswordField'
import PasswordStrength from './PasswordStrength'
import Spinner from './Spinner'

export default function ChangePasswordForm() {
  const { user } = useAuth()
  const notify = useNotify()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [errors, setErrors] = useState({})
  const [busy, setBusy] = useState(false)

  async function submit(e) {
    e.preventDefault()
    const found = {}
    if (!current) found.current = 'Enter your current password.'
    const pwError = validatePassword(next, user.username, user.email)
    if (pwError) found.next = pwError
    if (next !== confirm) found.confirm = 'Passwords do not match.'
    setErrors(found)
    if (Object.keys(found).length) return

    setBusy(true)
    try {
      await changePassword({ current_password: current, new_password: next })
      notify.success('Password changed. Other devices were logged out.')
      setCurrent(''); setNext(''); setConfirm('')
    } catch (err) {
      notify.error(describeError(err).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="card" onSubmit={submit} noValidate>
      <h2>Change password</h2>
      <PasswordField id="cp-current" label="Current password" value={current} onChange={setCurrent}
        autoComplete="current-password" error={errors.current} />
      <PasswordField id="cp-new" label="New password" value={next} onChange={setNext}
        autoComplete="new-password" error={errors.next} />
      <PasswordStrength password={next} username={user.username} email={user.email} />
      <PasswordField id="cp-confirm" label="Confirm new password" value={confirm} onChange={setConfirm}
        autoComplete="new-password" error={errors.confirm} />
      <button type="submit" className="btn primary" disabled={busy}>{busy ? <Spinner label="Saving" /> : 'Change password'}</button>
    </form>
  )
}
