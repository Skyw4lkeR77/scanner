import { useState, useEffect, useCallback, createContext, useContext } from 'react'
import { Routes, Route, Navigate, useNavigate, useLocation, Link } from 'react-router-dom'
import {
  Shield, LayoutDashboard, Scan, Users, FileText, Settings, LogOut,
  Menu, X, ChevronRight
} from 'lucide-react'
import api from './api/client'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import ScanPage from './pages/ScanPage'
import ScanDetailPage from './pages/ScanDetailPage'
import AdminUsersPage from './pages/AdminUsersPage'
import AdminLogsPage from './pages/AdminLogsPage'
import AdminDashboardPage from './pages/AdminDashboardPage'
import AdminJobsPage from './pages/AdminJobsPage'

// Auth context
const AuthContext = createContext(null)
export const useAuth = () => useContext(AuthContext)

function App() {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.me()
      .then(u => setUser(u))
      .catch(() => setUser(null))
      .finally(() => setLoading(false))
  }, [])

  // Listen for auth expiry from API client
  useEffect(() => {
    const handler = () => setUser(null)
    window.addEventListener('auth-expired', handler)
    return () => window.removeEventListener('auth-expired', handler)
  }, [])

  const handleLogin = useCallback((userData) => {
    setUser(userData)
  }, [])

  const handleLogout = useCallback(async () => {
    try { await api.logout() } catch { }
    setUser(null)
  }, [])

  if (loading) {
    return (
      <div className="loading-page">
        <div className="spinner" style={{ width: 40, height: 40 }} />
      </div>
    )
  }

  return (
    <AuthContext.Provider value={{ user, setUser: handleLogin, logout: handleLogout }}>
      <Routes>
        <Route path="/login" element={user ? <Navigate to="/" /> : <LoginPage />} />
        <Route path="/*" element={user ? <AppLayout /> : <Navigate to="/login" />} />
      </Routes>
    </AuthContext.Provider>
  )
}

function AppLayout() {
  const { user, logout } = useAuth()
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const location = useLocation()
  const navigate = useNavigate()

  const isAdmin = user?.role === 'admin'

  const navItems = [
    { label: 'Dashboard', icon: LayoutDashboard, path: '/' },
    { label: 'Scanner', icon: Scan, path: '/scan' },
  ]

  const adminItems = [
    { label: 'Admin Dashboard', icon: Shield, path: '/admin' },
    { label: 'Users', icon: Users, path: '/admin/users' },
    { label: 'All Jobs', icon: FileText, path: '/admin/jobs' },
    { label: 'Audit Logs', icon: Settings, path: '/admin/logs' },
  ]

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  return (
    <div className="app-layout">
      {/* Mobile toggle */}
      <button className="mobile-toggle" onClick={() => setSidebarOpen(!sidebarOpen)}>
        {sidebarOpen ? <X size={20} /> : <Menu size={20} />}
      </button>

      {/* Sidebar overlay for mobile */}
      {sidebarOpen && <div className="sidebar-overlay" onClick={() => setSidebarOpen(false)} />}

      {/* Sidebar */}
      <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
        <div className="sidebar-brand">
          <div className="logo">
            <Shield size={20} />
          </div>
          <div>
            <h1>OWASP Scanner</h1>
            <span className="subtitle">TOP 10 Vulnerability</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section">
            <div className="nav-section-title">Main</div>
            {navItems.map(item => (
              <Link
                key={item.path}
                to={item.path}
                className={`nav-link ${location.pathname === item.path ? 'active' : ''}`}
                onClick={() => setSidebarOpen(false)}
              >
                <item.icon />
                {item.label}
              </Link>
            ))}
          </div>

          {isAdmin && (
            <div className="nav-section">
              <div className="nav-section-title">Administration</div>
              {adminItems.map(item => (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`nav-link ${location.pathname === item.path ? 'active' : ''}`}
                  onClick={() => setSidebarOpen(false)}
                >
                  <item.icon />
                  {item.label}
                </Link>
              ))}
            </div>
          )}
        </nav>

        <div className="sidebar-footer">
          <div className="user-info">
            <div className="user-avatar">
              {user?.username?.[0]?.toUpperCase() || 'U'}
            </div>
            <div className="user-details">
              <div className="user-name">{user?.username}</div>
              <div className="user-role">{user?.role}</div>
            </div>
            <button className="btn-ghost" onClick={handleLogout} title="Logout">
              <LogOut size={18} />
            </button>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="main-content">
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/scan" element={<ScanPage />} />
          <Route path="/scan/:jobId" element={<ScanDetailPage />} />
          {isAdmin && (
            <>
              <Route path="/admin" element={<AdminDashboardPage />} />
              <Route path="/admin/users" element={<AdminUsersPage />} />
              <Route path="/admin/jobs" element={<AdminJobsPage />} />
              <Route path="/admin/logs" element={<AdminLogsPage />} />
            </>
          )}
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </main>
    </div>
  )
}

export default App
