// Client-side checks give quick feedback. The SERVER repeats every check and is the real authority.
const COMMON = new Set([
  'password', 'password1', 'password123', '123456', '12345678', '123456789', 'qwerty', 'qwerty123',
  'abc123', 'letmein', 'welcome', 'welcome1', 'admin', 'admin123', 'iloveyou', 'passw0rd', 'p@ssw0rd',
])

export const validateEmail = (v) =>
  /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v) && v.length <= 254 ? '' : 'Enter a valid email address.'

export const validateUsername = (v) =>
  /^[A-Za-z0-9_]{3,30}$/.test(v) ? '' : 'Use 3-30 letters, numbers or underscores.'

export function passwordRules(password, username = '', email = '') {
  const local = email.split('@')[0].toLowerCase()
  return [
    { label: 'At least 10 characters', ok: password.length >= 10 },
    { label: 'Not a very common password', ok: password.length > 0 && !COMMON.has(password.toLowerCase()) },
    { label: 'Not only digits', ok: password.length > 0 && !/^\d+$/.test(password) },
    {
      label: 'Does not contain your username or email name',
      ok: password.length > 0 &&
        !(username.length >= 3 && password.toLowerCase().includes(username.toLowerCase())) &&
        !(local.length >= 3 && password.toLowerCase().includes(local)),
    },
  ]
}

export const validatePassword = (password, username, email) => {
  const failed = passwordRules(password, username, email).find((r) => !r.ok)
  return failed ? `Password rule not met: ${failed.label}.` : ''
}
