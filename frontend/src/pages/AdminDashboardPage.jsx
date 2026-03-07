import { useState, useEffect } from 'react'
import {
    Shield, Users, Scan, AlertTriangle, ShieldAlert, Clock, Target
} from 'lucide-react'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, CartesianGrid } from 'recharts'
import api from '../api/client'

const SEV_COLORS = {
    info: '#60a5fa', low: '#facc15', medium: '#f97316', high: '#ef4444', critical: '#dc2626',
}

const OWASP_SHORT = {
    A01: 'Access Control', A02: 'Cryptography', A03: 'Injection',
    A04: 'Insecure Design', A05: 'Misconfiguration', A06: 'Outdated Components',
    A07: 'Auth Failures', A08: 'Data Integrity', A09: 'Logging', A10: 'SSRF',
}

export default function AdminDashboardPage() {
    const [stats, setStats] = useState(null)
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        api.adminDashboard()
            .then(setStats)
            .catch(() => { })
            .finally(() => setLoading(false))
    }, [])

    if (loading) return <div className="loading-page"><div className="spinner" /></div>

    const sevData = stats?.severity_counts
        ? Object.entries(stats.severity_counts).map(([name, value]) => ({ name, value }))
        : []

    const owaspData = stats?.owasp_counts
        ? Object.entries(stats.owasp_counts).map(([name, value]) => ({
            name, value, label: OWASP_SHORT[name] || name,
        }))
        : []

    return (
        <div className="animate-fade">
            <div className="page-header">
                <div>
                    <h1 className="page-title">Admin Dashboard</h1>
                    <p className="page-subtitle">System-wide overview and statistics</p>
                </div>
            </div>

            {/* Stats */}
            <div className="stats-grid">
                <div className="stat-card">
                    <div className="stat-icon blue"><Users /></div>
                    <div className="stat-value">{stats?.total_users || 0}</div>
                    <div className="stat-label">Total Users</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon green"><Scan /></div>
                    <div className="stat-value">{stats?.total_jobs || 0}</div>
                    <div className="stat-label">Total Scans</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon orange"><AlertTriangle /></div>
                    <div className="stat-value">{stats?.total_findings || 0}</div>
                    <div className="stat-label">Total Findings</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon purple"><Clock /></div>
                    <div className="stat-value">{stats?.queued_jobs || 0}</div>
                    <div className="stat-label">Queued Jobs</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon yellow"><Target /></div>
                    <div className="stat-value">{stats?.running_jobs || 0}</div>
                    <div className="stat-label">Running Jobs</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon red"><ShieldAlert /></div>
                    <div className="stat-value">
                        {(stats?.severity_counts?.critical || 0) + (stats?.severity_counts?.high || 0)}
                    </div>
                    <div className="stat-label">Critical + High</div>
                </div>
            </div>

            {/* Charts */}
            <div className="charts-grid">
                <div className="card">
                    <div className="card-header"><h3 className="card-title">Severity Distribution</h3></div>
                    {sevData.length > 0 ? (
                        <div className="chart-container">
                            <ResponsiveContainer>
                                <PieChart>
                                    <Pie data={sevData} cx="50%" cy="50%" innerRadius={60} outerRadius={100}
                                        dataKey="value" paddingAngle={3} label={({ name, value }) => `${name}: ${value}`}>
                                        {sevData.map((entry, i) => (
                                            <Cell key={i} fill={SEV_COLORS[entry.name] || '#6366f1'} />
                                        ))}
                                    </Pie>
                                    <Tooltip contentStyle={{
                                        background: '#1e293b', border: '1px solid rgba(255,255,255,0.1)',
                                        borderRadius: 8, color: '#f1f5f9',
                                    }} />
                                </PieChart>
                            </ResponsiveContainer>
                        </div>
                    ) : <div className="empty-state"><h3>No data</h3></div>}
                </div>

                <div className="card">
                    <div className="card-header"><h3 className="card-title">OWASP Top 10</h3></div>
                    {owaspData.length > 0 ? (
                        <div className="chart-container">
                            <ResponsiveContainer>
                                <BarChart data={owaspData} layout="vertical" margin={{ left: 80, right: 20 }}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                                    <XAxis type="number" stroke="#64748b" fontSize={12} />
                                    <YAxis type="category" dataKey="name" stroke="#64748b" fontSize={12} width={60} />
                                    <Tooltip contentStyle={{
                                        background: '#1e293b', border: '1px solid rgba(255,255,255,0.1)',
                                        borderRadius: 8, color: '#f1f5f9',
                                    }} />
                                    <Bar dataKey="value" fill="#6366f1" radius={[0, 4, 4, 0]} />
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    ) : <div className="empty-state"><h3>No data</h3></div>}
                </div>
            </div>

            {/* Recent Scans */}
            {stats?.recent_scans?.length > 0 && (
                <div className="card">
                    <div className="card-header"><h3 className="card-title">Recent Scans (All Users)</h3></div>
                    <div className="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Target</th>
                                    <th>Status</th>
                                    <th>Findings</th>
                                    <th>Date</th>
                                </tr>
                            </thead>
                            <tbody>
                                {stats.recent_scans.map(job => (
                                    <tr key={job.id}>
                                        <td>#{job.id}</td>
                                        <td style={{ maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis' }}>{job.target_url}</td>
                                        <td><span className={`badge badge-${job.status}`}>{job.status}</span></td>
                                        <td>{job.findings_count}</td>
                                        <td>{new Date(job.created_at).toLocaleString()}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </div>
    )
}
