import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import {
    Crosshair, Search, RefreshCw, ExternalLink, StopCircle, Clock,
    CheckCircle, XCircle, AlertCircle, Zap, Layers, Shield,
    Cpu, Globe
} from 'lucide-react'
import api from '../api/client'

const STATUS_ICONS = {
    queued: Clock,
    running: RefreshCw,
    completed: CheckCircle,
    failed: XCircle,
    stopped: AlertCircle,
}

const SCAN_MODES = {
    fast: {
        label: 'Fast Scan',
        description: 'Quick scan with basic templates (~5-15 min)',
        icon: Zap,
        color: 'var(--success-color)',
        time_estimate: '5-15 min'
    },
    deep: {
        label: 'Deep Scan',
        description: 'Crawling + Nuclei + Xray for thorough coverage (~30-60 min)',
        icon: Layers,
        color: 'var(--warning-color)',
        time_estimate: '30-60 min'
    },
    comprehensive: {
        label: 'Comprehensive Scan',
        description: 'Maximum coverage with all tools and extended timeout (~1-2 hours)',
        icon: Shield,
        color: 'var(--accent-color)',
        time_estimate: '1-2 hours'
    }
}

export default function ScanPage() {
    const [targetUrl, setTargetUrl] = useState('')
    const [scanNote, setScanNote] = useState('')
    const [scanMode, setScanMode] = useState('fast')
    const [submitting, setSubmitting] = useState(false)
    const [submitError, setSubmitError] = useState('')
    const [submitSuccess, setSubmitSuccess] = useState('')
    const [scannerStatus, setScannerStatus] = useState(null)

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

    const loadScannerStatus = useCallback(async () => {
        try {
            const status = await api.getScannerStatus()
            setScannerStatus(status)
        } catch { }
    }, [])

    useEffect(() => { 
        loadJobs()
        loadScannerStatus()
    }, [loadJobs, loadScannerStatus])

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
            setSubmitSuccess(`Scan submitted successfully! Mode: ${SCAN_MODES[scanMode].label}. It will start shortly.`)
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

    // Format duration from seconds
    const formatDuration = (seconds) => {
        if (!seconds) return '-'
        const hours = Math.floor(seconds / 3600)
        const mins = Math.floor((seconds % 3600) / 60)
        const secs = seconds % 60
        if (hours > 0) return `${hours}h ${mins}m ${secs}s`
        if (mins > 0) return `${mins}m ${secs}s`
        return `${secs}s`
    }

    // Format datetime in Asia/Jakarta timezone
    const formatDateTime = (dateStr) => {
        if (!dateStr) return '-'
        const date = new Date(dateStr)
        return date.toLocaleString('id-ID', {
            timeZone: 'Asia/Jakarta',
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        }) + ' WIB'
    }

    return (
        <div className="animate-fade">
            <div className="page-header">
                <div>
                    <h1 className="page-title">Security Scanner</h1>
                    <p className="page-subtitle">Submit targets and view scan history</p>
                </div>
                {scannerStatus && (
                    <div style={{ display: 'flex', gap: 'var(--space-2)', fontSize: 'var(--font-size-xs)' }}>
                        <span className={`badge ${scannerStatus.nuclei_available ? 'badge-success' : 'badge-error'}`}>
                            <Cpu size={10} /> Nuclei
                        </span>
                        <span className={`badge ${scannerStatus.katana_available ? 'badge-success' : 'badge-error'}`}>
                            <Globe size={10} /> Katana
                        </span>
                        <span className={`badge ${scannerStatus.xray_available ? 'badge-success' : 'badge-warning'}`}>
                            <Shield size={10} /> Xray
                        </span>
                    </div>
                )}
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
                    
                    {/* Scan Mode Selection */}
                    <div className="form-group">
                        <label className="form-label">Scan Mode</label>
                        <div style={{ 
                            display: 'grid', 
                            gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', 
                            gap: '1rem', 
                            marginTop: 8 
                        }}>
                            {Object.entries(SCAN_MODES).map(([mode, config]) => {
                                const Icon = config.icon
                                return (
                                    <label 
                                        key={mode}
                                        className="card" 
                                        style={{ 
                                            display: 'flex', 
                                            alignItems: 'flex-start', 
                                            gap: 12, 
                                            cursor: 'pointer', 
                                            padding: 16, 
                                            margin: 0, 
                                            border: scanMode === mode ? `2px solid ${config.color}` : '1px solid var(--border-color)',
                                            background: scanMode === mode ? `${config.color}10` : undefined
                                        }}
                                    >
                                        <input
                                            type="radio"
                                            name="scanMode"
                                            value={mode}
                                            checked={scanMode === mode}
                                            onChange={e => setScanMode(e.target.value)}
                                            style={{ marginTop: 4 }}
                                        />
                                        <div style={{ flex: 1 }}>
                                            <div style={{ 
                                                fontWeight: 600, 
                                                color: scanMode === mode ? config.color : 'var(--text-primary)',
                                                display: 'flex',
                                                alignItems: 'center',
                                                gap: 6
                                            }}>
                                                <Icon size={16} />
                                                {config.label}
                                            </div>
                                            <div style={{ 
                                                fontSize: 'var(--font-size-xs)', 
                                                color: 'var(--text-muted)',
                                                marginTop: 4,
                                                lineHeight: 1.4
                                            }}>
                                                {config.description}
                                            </div>
                                            <div style={{ 
                                                fontSize: 'var(--font-size-xs)', 
                                                color: 'var(--text-secondary)',
                                                marginTop: 8
                                            }}>
                                                <Clock size={10} style={{ display: 'inline', marginRight: 4 }} />
                                                Est. time: {config.time_estimate}
                                            </div>
                                        </div>
                                    </label>
                                )
                            })}
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
                                        <th>Mode</th>
                                        <th>Status</th>
                                        <th>Findings</th>
                                        <th>Duration</th>
                                        <th>Created (WIB)</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {jobs.map(job => {
                                        const Icon = STATUS_ICONS[job.status] || Clock
                                        const modeConfig = SCAN_MODES[job.scan_mode] || SCAN_MODES.fast
                                        return (
                                            <tr key={job.id}>
                                                <td>
                                                    <div style={{ maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                                        {job.target_url}
                                                    </div>
                                                    {job.scan_note && (
                                                        <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)' }}>
                                                            {job.scan_note}
                                                        </div>
                                                    )}
                                                    {job.endpoints_discovered > 0 && (
                                                        <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--success-color)' }}>
                                                            {job.endpoints_discovered} endpoints discovered
                                                        </div>
                                                    )}
                                                </td>
                                                <td>
                                                    <span className="badge" style={{ background: `${modeConfig.color}20`, color: modeConfig.color }}>
                                                        <modeConfig.icon size={10} style={{ marginRight: 4 }} />
                                                        {modeConfig.label}
                                                    </span>
                                                </td>
                                                <td>
                                                    <span className={`badge badge-${job.status}`}>
                                                        <Icon size={12} style={{ marginRight: 4 }} className={job.status === 'running' ? 'animate-pulse' : ''} />
                                                        {job.status}
                                                    </span>
                                                </td>
                                                <td>
                                                    <div style={{ fontWeight: 600 }}>{job.findings_count || 0}</div>
                                                    {job.nuclei_findings_count > 0 && job.xray_findings_count > 0 && (
                                                        <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)' }}>
                                                            N:{job.nuclei_findings_count} X:{job.xray_findings_count}
                                                        </div>
                                                    )}
                                                </td>
                                                <td>{formatDuration(job.scan_duration_seconds)}</td>
                                                <td>{formatDateTime(job.created_at)}</td>
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
