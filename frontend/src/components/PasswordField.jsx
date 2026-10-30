import { useState } from 'react'

export default function PasswordField({ id, label, value, onChange, error, autoComplete, onBlur }) {
  const [visible, setVisible] = useState(false)
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <div className="input-row">
        <input
          id={id} type={visible ? 'text' : 'password'} value={value} autoComplete={autoComplete}
          onChange={(e) => onChange(e.target.value)} onBlur={onBlur} maxLength={128}
          aria-invalid={Boolean(error)} aria-describedby={error ? `${id}-error` : undefined}
        />
        <button type="button" className="btn small" onClick={() => setVisible((v) => !v)} aria-pressed={visible}>
          {visible ? 'Hide' : 'Show'}
        </button>
      </div>
      {error && <p id={`${id}-error`} className="field-error" role="alert">{error}</p>}
    </div>
  )
}
