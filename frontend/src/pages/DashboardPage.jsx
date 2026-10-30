import { useCallback, useEffect, useState } from 'react'
import { useAuth } from '../context/AuthContext'
import { fetchDashboard } from '../services/authService'
import { describeError } from '../services/api'
import Navbar from '../components/Navbar'
import Spinner from '../components/Spinner'
import ChangePasswordForm from '../components/ChangePasswordForm'
import TwoFactorCard from '../components/TwoFactorCard'

const fmt = (iso) => (iso ? new Date(iso + 'Z').toLocaleString() : 'Never')

export default function DashboardPage() {
  const { user } = useAuth()
  const [tab, setTab] = useState('overview')
  const [stats, setStats] = useState(null)
  const [error, setError] = useState('')

  const load = useCallback(() => {
    fetchDashboard().then(setStats).catch((err) => setError(describeError(err).message))
  }, [])
  useEffect(() => { load() }, [load])

  const tabs = [['overview', 'Overview'], ['profile', 'Profile'], ['security', 'Security']]

  return (
    <>
      <Navbar />
      <main className="app">
        <h1>Welcome, {user.username}</h1>
        <nav className="tabs" role="tablist" aria-label="Dashboard sections">
          {tabs.map(([key, label]) => (
            <button key={key} type="button" role="tab" aria-selected={tab === key}
              className={tab === key ? 'tab active' : 'tab'} onClick={() => setTab(key)}>{label}</button>
          ))}
        </nav>

        {tab === 'overview' && (
          <section className="card">
            <h2>Account overview</h2>
            {error && <p className="field-error" role="alert">{error}</p>}
            {!stats && !error && <Spinner label="Loading dashboard" />}
            {stats && (
              <dl className="stats">
                <div><dt>Account age</dt><dd>{stats.account_age_days} day(s)</dd></div>
                <div><dt>Last login</dt><dd>{fmt(stats.last_login_at)}</dd></div>
                <div><dt>Active sessions</dt><dd>{stats.active_sessions}</dd></div>
                <div><dt>Two-factor auth</dt><dd>{stats.two_factor_enabled ? 'Enabled' : 'Off'}</dd></div>
                {stats.two_factor_enabled && (
                  <div><dt>Recovery codes left</dt><dd>{stats.recovery_codes_remaining}</dd></div>
                )}
              </dl>
            )}
            <p className="hint">These numbers are read from the server for your account only.</p>
          </section>
        )}

        {tab === 'profile' && (
          <section className="card">
            <h2>Profile</h2>
            <dl className="stats">
              <div><dt>Username</dt><dd>{user.username}</dd></div>
              <div><dt>Email</dt><dd>{user.email}</dd></div>
              <div><dt>Member since</dt><dd>{fmt(user.created_at)}</dd></div>
              <div><dt>User ID</dt><dd>{user.id}</dd></div>
            </dl>
          </section>
        )}

        {tab === 'security' && (
          <div className="grid">
            <ChangePasswordForm />
            <TwoFactorCard onChanged={load} />
          </div>
        )}
      </main>
    </>
  )
}
