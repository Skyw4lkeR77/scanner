import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import {
    Crosshair, Search, RefreshCw, ExternalLink, StopCircle, Clock,
    CheckCircle, XCircle, AlertCircle
} from 'lucide-react'
import api from '../api/client'

const STATUS_ICONS = {
    queued: Clock,
    running: RefreshCw,
    completed: CheckCircle,
    failed: XCircle,
    stopped: AlertCircle,
}

export default function ScanPage() {
    const [targetUrl, setTargetUrl] = useState('')
    const [scanNote, setScanNote] = useState('')
    const [scanMode, setScanMode] = useState('fast')
    const [submitting, setSubmitting] = useState(false)
    const [submitError, setSubmitError] = useState('')
    const [submitSuccess, setSubmitSuccess] = useState('')

    const [jobs, setJobs] = useState([])
    const [page, setPage] = useState(1)
    const [totalPages, setTotalPages] = useState(1)
    const [statusFilter, setStatusFilter] = useState('')
    const [loading, setLoading] = useState(true)

    const loadJobs = useCallback(async () => {
        try {
            const data = await api.listScans(page, statusFilter)
            setJobs(data.items)
            setTotalPages(data.pages)
        } catch { }
        setLoading(false)
    }, [page, statusFilter])

    useEffect(() => { loadJobs() }, [loadJobs])

    // Auto-refresh for active scans
    useEffect(() => {
        const hasActive = jobs.some(j => j.status === 'queued' || j.status === 'running')
        if (!hasActive) return
        const interval = setInterval(loadJobs, 5000)
        return () => clearInterval(interval)
    }, [jobs, loadJobs])

    const handleSubmit = async (e) => {
        e.preventDefault()
        setSubmitError('')
        setSubmitSuccess('')
        setSubmitting(true)
        try {
            await api.submitScan(targetUrl, scanNote || undefined, scanMode)
            setSubmitSuccess('Scan submitted successfully! It will start shortly.')
            setTargetUrl('')
            setScanNote('')
            setScanMode('fast')
            loadJobs()
        } catch (err) {
            setSubmitError(err.message)
        } finally {
            setSubmitting(false)
        }
    }

    const handleStop = async (jobId) => {
        if (!confirm('Stop this scan?')) return
        try {
            await api.stopScan(jobId)
            loadJobs()
        } catch (err) {
            alert(err.message)
        }
    }

    return (
        <div className="animate-fade">
            <div className="page-header">
                <div>
                    <h1 className="page-title">Scanner</h1>
                    <p className="page-subtitle">Submit targets and view scan history</p>
                </div>
            </div>

            {/* Submit Scan Form */}
            <div className="card" style={{ marginBottom: 'var(--space-6)' }}>
                <div className="card-header">
                    <h3 className="card-title"><Crosshair size={18} style={{ marginRight: 8 }} />New Scan</h3>
                </div>

                {submitError && <div className="alert alert-error">{submitError}</div>}
                {submitSuccess && <div className="alert alert-success">{submitSuccess}</div>}

                <form onSubmit={handleSubmit}>
                    <div className="form-group">
                        <label className="form-label" htmlFor="target-url">Target URL</label>
                        <input
                            id="target-url"
                            className="form-input"
                            type="url"
                            placeholder="https://example.com"
                            value={targetUrl}
                            onChange={e => setTargetUrl(e.target.value)}
                            required
                        />
                    </div>
                    <div className="form-group">
                        <label className="form-label" htmlFor="scan-note">Note (optional)</label>
                        <input
                            id="scan-note"
                            className="form-input"
                            type="text"
                            placeholder="Brief note about this scan..."
                            value={scanNote}
                            onChange={e => setScanNote(e.target.value)}
                            maxLength={500}
                        />
                    </div>
                    <div className="form-group">
                        <label className="form-label">Scan Mode</label>
                        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: '1rem', marginTop: 8 }}>
                            <label className="card" style={{ display: 'flex', alignItems: 'flex-start', gap: 12, cursor: 'pointer', padding: 12, margin: 0, border: scanMode === 'fast' ? '1px solid var(--primary-color)' : '' }}>
                                <input
                                    type="radio"
                                    name="scanMode"
                                    value="fast"
                                    checked={scanMode === 'fast'}
                                    onChange={e => setScanMode(e.target.value)}
                                    style={{ marginTop: 4 }}
                                />
                                <div>
                                    <div style={{ fontWeight: 500 }}>Fast Scan</div>
                                    <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', marginTop: 4 }}>Standard Nuclei vulnerability assessment on the target URL only.</div>
                                </div>
                            </label>
                            <label className="card" style={{ display: 'flex', alignItems: 'flex-start', gap: 12, cursor: 'pointer', padding: 12, margin: 0, border: scanMode === 'deep' ? '1px solid var(--warning-color)' : '' }}>
                                <input
                                    type="radio"
                                    name="scanMode"
                                    value="deep"
                                    checked={scanMode === 'deep'}
                                    onChange={e => setScanMode(e.target.value)}
                                    style={{ marginTop: 4 }}
                                />
                                <div>
                                    <div style={{ fontWeight: 500, color: 'var(--warning-color)' }}>Deep Scan (Katana + Nuclei)</div>
                                    <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', marginTop: 4 }}>Passively crawls the target to discover all endpoints and parameters before scanning. <strong>Significantly slower.</strong></div>
                                </div>
                            </label>
                        </div>
                    </div>
                    <button type="submit" className="btn btn-primary" disabled={submitting} style={{ marginTop: '1rem' }}>
                        {submitting ? <><div className="spinner" /> Submitting...</> : <><Crosshair size={16} /> Start Scan</>}
                    </button>
                </form>
            </div>

            {/* Scan History */}
            <div className="card">
                <div className="card-header">
                    <h3 className="card-title">Scan History</h3>
                    <button className="btn btn-sm btn-secondary" onClick={loadJobs}>
                        <RefreshCw size={14} /> Refresh
                    </button>
                </div>

                <div className="filters-bar">
                    <select
                        className="form-input"
                        value={statusFilter}
                        onChange={e => { setStatusFilter(e.target.value); setPage(1) }}
                        style={{ maxWidth: 200 }}
                    >
                        <option value="">All Status</option>
                        <option value="queued">Queued</option>
                        <option value="running">Running</option>
                        <option value="completed">Completed</option>
                        <option value="failed">Failed</option>
                        <option value="stopped">Stopped</option>
                    </select>
                </div>

                {loading ? (
                    <div className="empty-state"><div className="spinner" /></div>
                ) : jobs.length === 0 ? (
                    <div className="empty-state">
                        <Search size={48} />
                        <h3>No scans found</h3>
                        <p>Submit a target above to start scanning</p>
                    </div>
                ) : (
                    <>
                        <div className="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Target</th>
                                        <th>Status</th>
                                        <th>Findings</th>
                                        <th>Date</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {jobs.map(job => {
                                        const Icon = STATUS_ICONS[job.status] || Clock
                                        return (
                                            <tr key={job.id}>
                                                <td>
                                                    <div style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                                        {job.target_url}
                                                    </div>
                                                    {job.scan_note && (
                                                        <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)' }}>
                                                            {job.scan_note}
                                                        </div>
                                                    )}
                                                </td>
                                                <td>
                                                    <span className={`badge badge-${job.status}`}>
                                                        <Icon size={12} style={{ marginRight: 4 }} className={job.status === 'running' ? 'animate-pulse' : ''} />
                                                        {job.status}
                                                    </span>
                                                </td>
                                                <td>{job.findings_count}</td>
                                                <td>{new Date(job.created_at).toLocaleString()}</td>
                                                <td>
                                                    <div className="table-actions">
                                                        <Link to={`/scan/${job.id}`} className="btn btn-sm btn-secondary">
                                                            <ExternalLink size={12} /> View
                                                        </Link>
                                                        {(job.status === 'queued' || job.status === 'running') && (
                                                            <button className="btn btn-sm btn-danger" onClick={() => handleStop(job.id)}>
                                                                <StopCircle size={12} /> Stop
                                                            </button>
                                                        )}
                                                    </div>
                                                </td>
                                            </tr>
                                        )
                                    })}
                                </tbody>
                            </table>
                        </div>

                        {totalPages > 1 && (
                            <div className="pagination">
                                <button disabled={page <= 1} onClick={() => setPage(p => p - 1)}>Previous</button>
                                <span style={{ color: 'var(--text-muted)', fontSize: 'var(--font-size-sm)' }}>
                                    Page {page} of {totalPages}
                                </span>
                                <button disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>Next</button>
                            </div>
                        )}
                    </>
                )}
            </div>
        </div>
    )
}
