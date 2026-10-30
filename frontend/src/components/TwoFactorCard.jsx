import { useState } from 'react'
import { disableTwoFactor, enableTwoFactor, setupTwoFactor } from '../services/authService'
import { describeError } from '../services/api'
import { useAuth } from '../context/AuthContext'
import { useNotify } from '../context/NotificationContext'
import PasswordField from './PasswordField'
import TextField from './TextField'
import Spinner from './Spinner'

export default function TwoFactorCard({ onChanged }) {
  const { user, refreshUser } = useAuth()
  const notify = useNotify()
  const [step, setStep] = useState('idle') // idle | password | scan | codes | disable
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [setup, setSetup] = useState(null)
  const [recovery, setRecovery] = useState([])
  const [busy, setBusy] = useState(false)

  const reset = () => { setStep('idle'); setPassword(''); setCode(''); setSetup(null) }

  async function run(action, onOk) {
    setBusy(true)
    try { await onOk(await action()) } catch (err) { notify.error(describeError(err).message) } finally { setBusy(false) }
  }

  const startSetup = (e) => {
    e.preventDefault()
    run(() => setupTwoFactor(password), (data) => { setSetup(data); setPassword(''); setStep('scan') })
  }
  const confirmEnable = (e) => {
    e.preventDefault()
    run(() => enableTwoFactor(code), async (data) => {
      setRecovery(data.recovery_codes); setSetup(null); setCode(''); setStep('codes')
      await refreshUser(); onChanged?.()
      notify.success('Two-factor authentication is now enabled.')
    })
  }
  const confirmDisable = (e) => {
    e.preventDefault()
    run(() => disableTwoFactor({ password, code }), async () => {
      reset(); await refreshUser(); onChanged?.()
      notify.success('Two-factor authentication disabled.')
    })
  }

  return (
    <section className="card">
      <h2>Two-factor authentication (TOTP)</h2>
      <p className="hint">
        Status: <strong className={user.two_factor_enabled ? 'good' : 'warn'}>
          {user.two_factor_enabled ? 'Enabled' : 'Not enabled'}
        </strong>
      </p>

      {step === 'idle' && !user.two_factor_enabled && (
        <button type="button" className="btn primary" onClick={() => setStep('password')}>Set up 2FA</button>
      )}
      {step === 'idle' && user.two_factor_enabled && (
        <button type="button" className="btn" onClick={() => setStep('disable')}>Disable 2FA</button>
      )}

      {step === 'password' && (
        <form onSubmit={startSetup}>
          <p>Confirm your password to continue.</p>
          <PasswordField id="tf-password" label="Current password" value={password} onChange={setPassword} autoComplete="current-password" />
          <div className="actions">
            <button type="submit" className="btn primary" disabled={busy || !password}>{busy ? <Spinner /> : 'Continue'}</button>
            <button type="button" className="btn" onClick={reset}>Cancel</button>
          </div>
        </form>
      )}

      {step === 'scan' && setup && (
        <form onSubmit={confirmEnable}>
          <p>Scan this QR code with an authenticator app (Google Authenticator, Microsoft Authenticator, Authy...).</p>
          <img className="qr" src={setup.qr_svg_data_uri} alt="QR code for your authenticator app" />
          <p className="hint">Can't scan? Enter this key manually:</p>
          <code className="secret">{setup.secret}</code>
          <TextField id="tf-code" label="6-digit code from the app" value={code} inputMode="numeric"
            autoComplete="one-time-code" maxLength={6} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} />
          <div className="actions">
            <button type="submit" className="btn primary" disabled={busy || code.length !== 6}>{busy ? <Spinner /> : 'Verify and enable'}</button>
            <button type="button" className="btn" onClick={reset}>Cancel</button>
          </div>
        </form>
      )}

      {step === 'codes' && (
        <div>
          <p><strong>Save these recovery codes now.</strong> Each works once if you lose your phone. They will not be shown again.</p>
          <ul className="codes">{recovery.map((c) => <li key={c}><code>{c}</code></li>)}</ul>
          <button type="button" className="btn primary" onClick={() => { setRecovery([]); reset() }}>I have saved them</button>
        </div>
      )}

      {step === 'disable' && (
        <form onSubmit={confirmDisable}>
          <PasswordField id="td-password" label="Current password" value={password} onChange={setPassword} autoComplete="current-password" />
          <TextField id="td-code" label="Authenticator code or recovery code" value={code}
            autoComplete="one-time-code" maxLength={40} onChange={(e) => setCode(e.target.value)} />
          <div className="actions">
            <button type="submit" className="btn danger" disabled={busy || !password || code.length < 6}>{busy ? <Spinner /> : 'Disable 2FA'}</button>
            <button type="button" className="btn" onClick={reset}>Cancel</button>
          </div>
        </form>
      )}
    </section>
  )
}
