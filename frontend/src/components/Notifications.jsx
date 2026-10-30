import { useNotify } from '../context/NotificationContext'

export default function Notifications() {
  const { items, dismiss } = useNotify()
  return (
    <div className="toasts" aria-live="polite">
      {items.map((n) => (
        <div key={n.id} className={`toast ${n.type}`} role={n.type === 'error' ? 'alert' : 'status'}>
          <span>{n.message}</span>
          <button type="button" aria-label="Dismiss notification" onClick={() => dismiss(n.id)}>×</button>
        </div>
      ))}
    </div>
  )
}
