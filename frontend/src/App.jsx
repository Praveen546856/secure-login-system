import { Link, Navigate, Route, Routes } from 'react-router-dom'
import LoginPage from './pages/LoginPage'
import RegisterPage from './pages/RegisterPage'
import DashboardPage from './pages/DashboardPage'
import ProtectedRoute from './components/ProtectedRoute'
import Notifications from './components/Notifications'

export default function App() {
  return (
    <>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/dashboard" element={<ProtectedRoute><DashboardPage /></ProtectedRoute>} />
        <Route path="*" element={
          <main className="auth-page"><div className="card auth-card center-text">
            <h1>Page not found</h1><Link to="/dashboard">Go to dashboard</Link>
          </div></main>
        } />
      </Routes>
      <Notifications />
    </>
  )
}
