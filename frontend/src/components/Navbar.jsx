import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { useNotify } from '../context/NotificationContext'
import Spinner from './Spinner'

export default function Navbar() {
  const { user, logout } = useAuth()
  const notify = useNotify()
  const navigate = useNavigate()
  const [busy, setBusy] = useState(false)

  async function handleLogout() {
    setBusy(true)
    try {
      await logout()
      notify.success('You have been logged out.')
    } catch {
      notify.info('Logged out on this device.')
    } finally {
      setBusy(false)
      navigate('/login', { replace: true })
    }
  }

  return (
    <header className="navbar">
      <span className="brand">🔐 Secure Login System</span>
      <div className="nav-right">
        <span className="nav-user">{user?.username}</span>
        <button type="button" className="btn small" onClick={handleLogout} disabled={busy}>
          {busy ? <Spinner label="Logging out" /> : 'Log out'}
        </button>
      </div>
    </header>
  )
}
