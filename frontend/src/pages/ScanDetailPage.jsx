import { useState, useEffect, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
    ArrowLeft, Download, RefreshCw, Shield, ExternalLink,
    AlertTriangle, Tag, FileText, CheckCircle, XCircle, Eye
} from 'lucide-react'
import api from '../api/client'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const OWASP_NAMES = {
    A01: 'Broken Access Control',
    A02: 'Cryptographic Failures',
    A03: 'Injection',
    A04: 'Insecure Design',
    A05: 'Security Misconfiguration',
    A06: 'Vulnerable & Outdated Components',
    A07: 'Auth Failures',
    A08: 'Software & Data Integrity',
    A09: 'Logging & Monitoring',
    A10: 'SSRF',
}

export default function ScanDetailPage() {
    const { jobId } = useParams()
    const [job, setJob] = useState(null)
    const [findings, setFindings] = useState([])
    const [totalFindings, setTotalFindings] = useState(0)
    const [page, setPage] = useState(1)
    const [totalPages, setTotalPages] = useState(1)
    const [sevFilter, setSevFilter] = useState('')
    const [owaspFilter, setOwaspFilter] = useState('')
    const [groupBy, setGroupBy] = useState('severity')
    const [loading, setLoading] = useState(true)
    const [expandedId, setExpandedId] = useState(null)

    const loadJob = useCallback(async () => {
        try {
            const data = await api.getScan(jobId)
            setJob(data)
        } catch { }
    }, [jobId])

    const loadFindings = useCallback(async () => {
        try {
            const data = await api.getFindings(jobId, page, sevFilter, owaspFilter)
            setFindings(data.items)
            setTotalFindings(data.total)
            setTotalPages(data.pages)
        } catch { }
        setLoading(false)
    }, [jobId, page, sevFilter, owaspFilter])

    useEffect(() => { loadJob(); loadFindings() }, [loadJob, loadFindings])

    // Auto-refresh while running
    useEffect(() => {
        if (!job || !['queued', 'running'].includes(job.status)) return
        const interval = setInterval(() => { loadJob(); loadFindings() }, 5000)
        return () => clearInterval(interval)
    }, [job, loadJob, loadFindings])

    const handleMark = async (findingId, status) => {
        try {
            await api.markFinding(findingId, status)
            loadFindings()
        } catch (err) {
            alert(err.message)
        }
    }

    const handleExport = async (format) => {
        try {
            const res = await api.exportFindings(jobId, format)
            const blob = await res.blob()
            const url = URL.createObjectURL(blob)
            const a = document.createElement('a')
            a.href = url
            a.download = `findings-${jobId}.${format}`
            a.click()
            URL.revokeObjectURL(url)
        } catch (err) {
            alert(err.message)
        }
    }

    // Group findings
    const grouped = {}
    findings.forEach(f => {
        const key = groupBy === 'severity' ? f.severity : (f.owasp_category || 'Uncategorized')
        if (!grouped[key]) grouped[key] = []
        grouped[key].push(f)
    })

    const sortedGroups = groupBy === 'severity'
        ? SEV_ORDER.filter(s => grouped[s])
        : Object.keys(grouped).sort()

    if (!job && loading) return <div className="loading-page"><div className="spinner" /></div>

    return (
        <div className="animate-fade">
            <Link to="/scan" className="btn btn-sm btn-secondary" style={{ marginBottom: 'var(--space-4)' }}>
                <ArrowLeft size={14} /> Back to Scans
            </Link>

            {/* Job Info */}
            <div className="card" style={{ marginBottom: 'var(--space-6)' }}>
                <div className="card-header">
                    <h3 className="card-title">Scan Details</h3>
                    <span className={`badge badge-${job?.status}`}>{job?.status}</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 'var(--space-4)' }}>
                    <div>
                        <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)' }}>Target</div>
                        <div style={{ fontSize: 'var(--font-size-sm)', wordBreak: 'break-all' }}>{job?.target_url}</div>
                    </div>
                    <div>
                        <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)' }}>Created</div>
                        <div style={{ fontSize: 'var(--font-size-sm)' }}>{job?.created_at ? new Date(job.created_at).toLocaleString() : '-'}</div>
                    </div>
                    <div>
                        <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)' }}>Completed</div>
                        <div style={{ fontSize: 'var(--font-size-sm)' }}>{job?.finished_at ? new Date(job.finished_at).toLocaleString() : '-'}</div>
                    </div>
                    <div>
                        <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)' }}>Findings</div>
                        <div style={{ fontSize: 'var(--font-size-sm)', fontWeight: 600 }}>{job?.findings_count || 0}</div>
                    </div>
                </div>
                {job?.error_message && (
                    <div className="alert alert-error" style={{ marginTop: 'var(--space-4)' }}>
                        {job.error_message}
                    </div>
                )}
                {job?.status === 'running' && (
                    <div style={{ marginTop: 'var(--space-4)' }}>
                        <div style={{
                            height: 4, background: 'var(--bg-glass)', borderRadius: 'var(--radius-full)', overflow: 'hidden',
                        }}>
                            <div style={{
                                height: '100%', width: `${job.progress_pct}%`, background: 'var(--accent)',
                                borderRadius: 'var(--radius-full)', transition: 'width 0.5s ease',
                            }} />
                        </div>
                        <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', marginTop: 'var(--space-1)' }}>
                            {job.progress_pct}% complete • Scanning...
                        </div>
                    </div>
                )}
            </div>

            {/* Findings Section */}
            <div className="card">
                <div className="card-header" style={{ flexWrap: 'wrap', gap: 'var(--space-3)' }}>
                    <h3 className="card-title">Findings ({totalFindings})</h3>
                    <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                        <button className="btn btn-sm btn-secondary" onClick={() => handleExport('json')}>
                            <Download size={12} /> JSON
                        </button>
                        <button className="btn btn-sm btn-secondary" onClick={() => handleExport('csv')}>
                            <Download size={12} /> CSV
                        </button>
                        <button className="btn btn-sm btn-secondary" onClick={() => { loadJob(); loadFindings() }}>
                            <RefreshCw size={12} />
                        </button>
                    </div>
                </div>

                <div className="filters-bar">
                    <select className="form-input" value={sevFilter} onChange={e => { setSevFilter(e.target.value); setPage(1) }} style={{ maxWidth: 160 }}>
                        <option value="">All Severity</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                        <option value="info">Info</option>
                    </select>
                    <select className="form-input" value={owaspFilter} onChange={e => { setOwaspFilter(e.target.value); setPage(1) }} style={{ maxWidth: 200 }}>
                        <option value="">All OWASP</option>
                        {Object.entries(OWASP_NAMES).map(([k, v]) => (
                            <option key={k} value={k}>{k}: {v}</option>
                        ))}
                    </select>
                    <select className="form-input" value={groupBy} onChange={e => setGroupBy(e.target.value)} style={{ maxWidth: 160 }}>
                        <option value="severity">Group by Severity</option>
                        <option value="owasp">Group by OWASP</option>
                    </select>
                </div>

                {loading ? (
                    <div className="empty-state"><div className="spinner" /></div>
                ) : findings.length === 0 ? (
                    <div className="empty-state">
                        <Shield size={48} />
                        <h3>No findings</h3>
                        <p>{job?.status === 'completed' ? 'No vulnerabilities detected' : 'Findings will appear here once scan completes'}</p>
                    </div>
                ) : (
                    <>
                        {sortedGroups.map(group => (
                            <div key={group} style={{ marginBottom: 'var(--space-6)' }}>
                                <h4 style={{
                                    fontSize: 'var(--font-size-sm)', fontWeight: 600, textTransform: 'uppercase',
                                    letterSpacing: '0.06em', marginBottom: 'var(--space-3)', display: 'flex',
                                    alignItems: 'center', gap: 'var(--space-2)',
                                }}>
                                    <span className={`badge badge-${group}`}>{group}</span>
                                    {groupBy === 'owasp' && OWASP_NAMES[group] && (
                                        <span style={{ color: 'var(--text-muted)', fontWeight: 400, textTransform: 'none' }}>
                                            {OWASP_NAMES[group]}
                                        </span>
                                    )}
                                    <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>
                                        ({grouped[group].length})
                                    </span>
                                </h4>

                                {grouped[group].map(f => (
                                    <div key={f.id} className="finding-card">
                                        <div className="finding-header">
                                            <div>
                                                <span className="finding-name">{f.name}</span>
                                                <div className="finding-meta">
                                                    <span><Tag size={12} />{f.rule_id}</span>
                                                    {f.cwe && <span>CWE: {f.cwe}</span>}
                                                    {f.owasp_category && <span>OWASP: {f.owasp_category}</span>}
                                                    {f.matched_url && (
                                                        <span><ExternalLink size={12} />{f.matched_url.length > 60 ? f.matched_url.slice(0, 60) + '...' : f.matched_url}</span>
                                                    )}
                                                </div>
                                            </div>
                                            <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
                                                <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                                                <button
                                                    className="btn btn-sm btn-ghost"
                                                    onClick={() => setExpandedId(expandedId === f.id ? null : f.id)}
                                                >
                                                    <Eye size={14} />
                                                </button>
                                            </div>
                                        </div>

                                        {expandedId === f.id && (
                                            <div className="animate-fade">
                                                {f.description && <div className="finding-desc">{f.description}</div>}
                                                {f.evidence && (
                                                    <div>
                                                        <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', marginTop: 'var(--space-3)' }}>Evidence:</div>
                                                        <div className="finding-evidence">{f.evidence}</div>
                                                    </div>
                                                )}
                                                {f.remediation && (
                                                    <div style={{ marginTop: 'var(--space-3)', fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)' }}>
                                                        <strong>Remediation:</strong> {f.remediation}
                                                    </div>
                                                )}
                                                <div style={{ marginTop: 'var(--space-3)', display: 'flex', gap: 'var(--space-2)' }}>
                                                    <span style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', alignSelf: 'center' }}>
                                                        Status: <span className={`badge badge-${f.status === 'false_positive' ? 'warning' : f.status === 'confirmed' ? 'danger' : 'default'}`}>{f.status}</span>
                                                    </span>
                                                    <button className="btn btn-sm btn-secondary" onClick={() => handleMark(f.id, 'false_positive')}>
                                                        <XCircle size={12} /> False Positive
                                                    </button>
                                                    <button className="btn btn-sm btn-secondary" onClick={() => handleMark(f.id, 'needs_review')}>
                                                        <AlertTriangle size={12} /> Needs Review
                                                    </button>
                                                    <button className="btn btn-sm btn-secondary" onClick={() => handleMark(f.id, 'confirmed')}>
                                                        <CheckCircle size={12} /> Confirmed
                                                    </button>
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                ))}
                            </div>
                        ))}

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
