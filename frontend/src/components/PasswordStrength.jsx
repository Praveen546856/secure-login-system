import { passwordRules } from '../validation'

export default function PasswordStrength({ password, username, email }) {
  if (!password) return null
  const rules = passwordRules(password, username, email)
  return (
    <ul className="rules" aria-label="Password requirements">
      {rules.map((r) => (
        <li key={r.label} className={r.ok ? 'ok' : 'bad'}>
          <span aria-hidden="true">{r.ok ? '✓' : '✗'}</span> {r.label}
        </li>
      ))}
    </ul>
  )
}
