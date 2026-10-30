import api from './api'

export const register = (payload) => api.post('/auth/register', payload).then((r) => r.data)
export const login = (payload) => api.post('/auth/login', payload).then((r) => r.data)
export const loginTwoFactor = (payload) => api.post('/auth/login/2fa', payload).then((r) => r.data)
export const logout = () => api.post('/auth/logout').then((r) => r.data)
export const fetchMe = () => api.get('/auth/me').then((r) => r.data)
export const fetchDashboard = () => api.get('/dashboard').then((r) => r.data)
export const changePassword = (payload) => api.post('/auth/change-password', payload).then((r) => r.data)
export const setupTwoFactor = (password) => api.post('/auth/2fa/setup', { password }).then((r) => r.data)
export const enableTwoFactor = (code) => api.post('/auth/2fa/enable', { code }).then((r) => r.data)
export const disableTwoFactor = (payload) => api.post('/auth/2fa/disable', payload).then((r) => r.data)
