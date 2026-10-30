import { createContext, useCallback, useContext, useMemo, useState } from 'react'

const NotificationContext = createContext(null)
let nextId = 1

export function NotificationProvider({ children }) {
  const [items, setItems] = useState([])

  const dismiss = useCallback((id) => setItems((list) => list.filter((n) => n.id !== id)), [])
  const notify = useCallback((type, message) => {
    const id = nextId++
    setItems((list) => [...list, { id, type, message }])
    setTimeout(() => dismiss(id), 6000)
  }, [dismiss])

  const value = useMemo(() => ({
    items, dismiss,
    success: (m) => notify('success', m),
    error: (m) => notify('error', m),
    info: (m) => notify('info', m),
  }), [items, dismiss, notify])

  return <NotificationContext.Provider value={value}>{children}</NotificationContext.Provider>
}

export const useNotify = () => useContext(NotificationContext)
