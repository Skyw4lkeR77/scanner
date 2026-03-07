import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
    Scan, Target, AlertTriangle, ShieldAlert, ShieldCheck, Clock,
    ArrowRight, Crosshair
} from 'lucide-react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import api from '../api/client'

const SEV_COLORS = {
    info: '#60a5fa',
    low: '#facc15',
    medium: '#f97316',
    high: '#ef4444',
    critical: '#dc2626',
}

export default function DashboardPage() {
    const [stats, setStats] = useState(null)
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        api.dashboard()
            .then(setStats)
            .catch(() => { })
            .finally(() => setLoading(false))
    }, [])

    if (loading) return <div className="loading-page"><div className="spinner" /></div>

    const sevData = stats?.severity_counts
        ? Object.entries(stats.severity_counts).map(([name, value]) => ({ name, value }))
        : []

    return (
        <div className="animate-fade">
            <div className="page-header">
                <div>
                    <h1 className="page-title">Dashboard</h1>
                    <p className="page-subtitle">Overview of your scanning activity</p>
                </div>
                <Link to="/scan" className="btn btn-primary">
                    <Crosshair size={16} /> New Scan
                </Link>
            </div>

            {/* Stats */}
            <div className="stats-grid">
                <div className="stat-card">
                    <div className="stat-icon blue"><Scan /></div>
                    <div className="stat-value">{stats?.total_jobs || 0}</div>
                    <div className="stat-label">Total Scans</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon purple"><Clock /></div>
                    <div className="stat-value">{(stats?.queued_jobs || 0) + (stats?.running_jobs || 0)}</div>
                    <div className="stat-label">Active Scans</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon orange"><AlertTriangle /></div>
                    <div className="stat-value">{stats?.total_findings || 0}</div>
                    <div className="stat-label">Total Findings</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon red"><ShieldAlert /></div>
                    <div className="stat-value">
                        {(stats?.severity_counts?.critical || 0) + (stats?.severity_counts?.high || 0)}
                    </div>
                    <div className="stat-label">Critical + High</div>
                </div>
            </div>

            {/* Charts + Recent */}
            <div className="charts-grid">
                {/* Severity Pie Chart */}
                <div className="card">
                    <div className="card-header">
                        <h3 className="card-title">Findings by Severity</h3>
                    </div>
                    {sevData.length > 0 ? (
                        <div className="chart-container">
                            <ResponsiveContainer>
                                <PieChart>
                                    <Pie
                                        data={sevData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={60}
                                        outerRadius={100}
                                        dataKey="value"
                                        paddingAngle={3}
                                        label={({ name, value }) => `${name}: ${value}`}
                                    >
                                        {sevData.map((entry, i) => (
                                            <Cell key={i} fill={SEV_COLORS[entry.name] || '#6366f1'} />
                                        ))}
                                    </Pie>
                                    <Tooltip
                                        contentStyle={{
                                            background: '#1e293b', border: '1px solid rgba(255,255,255,0.1)',
                                            borderRadius: 8, color: '#f1f5f9',
                                        }}
                                    />
                                </PieChart>
                            </ResponsiveContainer>
                        </div>
                    ) : (
                        <div className="empty-state">
                            <ShieldCheck size={48} />
                            <h3>No findings yet</h3>
                            <p>Start a scan to see vulnerability distribution</p>
                        </div>
                    )}
                </div>

                {/* Recent Scans */}
                <div className="card">
                    <div className="card-header">
                        <h3 className="card-title">Recent Scans</h3>
                        <Link to="/scan" className="btn btn-sm btn-secondary">View All <ArrowRight size={14} /></Link>
                    </div>
                    {stats?.recent_scans?.length > 0 ? (
                        <div>
                            {stats.recent_scans.map(job => (
                                <Link
                                    key={job.id}
                                    to={`/scan/${job.id}`}
                                    style={{
                                        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                        padding: 'var(--space-3)', borderBottom: '1px solid var(--border-color)',
                                        color: 'inherit', textDecoration: 'none',
                                    }}
                                >
                                    <div>
                                        <div style={{ fontSize: 'var(--font-size-sm)', fontWeight: 500 }}>
                                            {job.target_url.length > 40 ? job.target_url.slice(0, 40) + '...' : job.target_url}
                                        </div>
                                        <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)' }}>
                                            {new Date(job.created_at).toLocaleString()}
                                        </div>
                                    </div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                                        <span className={`badge badge-${job.status}`}>{job.status}</span>
                                        {job.findings_count > 0 && (
                                            <span style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)' }}>
                                                {job.findings_count} findings
                                            </span>
                                        )}
                                    </div>
                                </Link>
                            ))}
                        </div>
                    ) : (
                        <div className="empty-state">
                            <Target size={48} />
                            <h3>No scans yet</h3>
                            <p>Submit a target URL to start scanning</p>
                        </div>
                    )}
                </div>
            </div>

            {/* OWASP Distribution */}
            {stats?.owasp_counts && Object.keys(stats.owasp_counts).length > 0 && (
                <div className="card">
                    <div className="card-header">
                        <h3 className="card-title">OWASP Top 10 Distribution</h3>
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-3)' }}>
                        {Object.entries(stats.owasp_counts)
                            .sort(([, a], [, b]) => b - a)
                            .map(([cat, count]) => (
                                <div key={cat} className="stat-card" style={{ minWidth: 120 }}>
                                    <div className="stat-value" style={{ fontSize: 'var(--font-size-xl)' }}>{count}</div>
                                    <div className="stat-label">{cat}</div>
                                </div>
                            ))}
                    </div>
                </div>
            )}
        </div>
    )
}
