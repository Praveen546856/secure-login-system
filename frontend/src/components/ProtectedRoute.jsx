import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import Spinner from './Spinner'

// Only a UI convenience. The REAL protection is on the server: every protected API call
// needs a valid session cookie, so hiding a page here never replaces server-side checks.
export default function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  const location = useLocation()
  if (loading) return <div className="center"><Spinner label="Checking session" /></div>
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname }} />
  return children
}
