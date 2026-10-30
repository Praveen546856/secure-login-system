export default function TextField({ id, label, error, ...props }) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input id={id} aria-invalid={Boolean(error)} aria-describedby={error ? `${id}-error` : undefined} {...props} />
      {error && <p id={`${id}-error`} className="field-error" role="alert">{error}</p>}
    </div>
  )
}
