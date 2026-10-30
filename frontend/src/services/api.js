import axios from 'axios'

// The CSRF token lives ONLY in memory (a JS variable). It is never written to
// localStorage/sessionStorage, and the session cookie itself is HttpOnly, so
// JavaScript can never read it.
let csrfToken = null
let onUnauthorized = null

export const setCsrfToken = (token) => { csrfToken = token }
export const setUnauthorizedHandler = (fn) => { onUnauthorized = fn }

const api = axios.create({
  baseURL: '/api',
  withCredentials: true,
  headers: { 'Content-Type': 'application/json' },
  timeout: 15000,
})

api.interceptors.request.use((config) => {
  const method = (config.method || 'get').toLowerCase()
  if (csrfToken && method !== 'get') config.headers['X-CSRF-Token'] = csrfToken
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    // A 401 on a protected call means the session ended (logout elsewhere, expiry, ...).
    const url = error.config?.url || ''
    const isAuthAttempt = url.startsWith('/auth/login') || url === '/auth/me'
    if (error.response?.status === 401 && !isAuthAttempt && onUnauthorized) onUnauthorized()
    return Promise.reject(error)
  },
)

// Turn an Axios error into { message, fields } for the UI.
export function describeError(error) {
  if (!error.response) {
    return { message: 'Cannot reach the server. Is the backend running?', fields: {} }
  }
  const { status, data, headers } = error.response
  if (status === 422 && Array.isArray(data?.errors)) {
    const fields = {}
    for (const e of data.errors) if (e.field && !fields[e.field]) fields[e.field] = e.message
    return { message: 'Please fix the highlighted fields.', fields }
  }
  if (status === 429) {
    const wait = Number(headers?.['retry-after'])
    const when = wait ? ` Try again in about ${Math.ceil(wait / 60)} minute(s).` : ''
    return { message: `Too many attempts.${when}`, fields: {} }
  }
  return { message: typeof data?.detail === 'string' ? data.detail : 'Something went wrong.', fields: {} }
}

export default api
