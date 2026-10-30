import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { setCsrfToken, setUnauthorizedHandler } from '../services/api'
import * as authService from '../services/authService'
import { useNotify } from './NotificationContext'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true) // true while we ask the server "who am I?"
  const notify = useNotify()

  const applySession = useCallback((data) => {
    setCsrfToken(data.csrf_token)
    setUser(data.user)
  }, [])

  const clearSession = useCallback(() => {
    setCsrfToken(null)
    setUser(null)
  }, [])

  // On page load/refresh the browser still has its HttpOnly cookie. Ask the server if it is valid.
  useEffect(() => {
    authService.fetchMe()
      .then(applySession)
      .catch(clearSession)
      .finally(() => setLoading(false))
  }, [applySession, clearSession])

  useEffect(() => {
    setUnauthorizedHandler(() => {
      clearSession()
      notify.info('Your session has ended. Please log in again.')
    })
  }, [clearSession, notify])

  // Returns { twoFactorChallenge } when a 2FA code is still needed.
  const login = useCallback(async (email, password) => {
    const data = await authService.login({ email, password })
    if (data.two_factor_required) return { twoFactorChallenge: data.challenge }
    applySession(data)
    return {}
  }, [applySession])

  const loginTwoFactor = useCallback(async (challenge, code) => {
    applySession(await authService.loginTwoFactor({ challenge, code }))
  }, [applySession])

  const logout = useCallback(async () => {
    try { await authService.logout() } finally { clearSession() }
  }, [clearSession])

  const refreshUser = useCallback(async () => applySession(await authService.fetchMe()), [applySession])

  const value = useMemo(
    () => ({ user, loading, login, loginTwoFactor, logout, refreshUser }),
    [user, loading, login, loginTwoFactor, logout, refreshUser],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export const useAuth = () => useContext(AuthContext)
