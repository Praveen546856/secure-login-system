export default function Spinner({ label = 'Loading' }) {
  return <span className="spinner" role="status" aria-label={label} />
}
