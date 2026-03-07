import { useState, useEffect, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
    ArrowLeft, Download, RefreshCw, Shield, ExternalLink,
    AlertTriangle, Tag, FileText, CheckCircle, XCircle, Eye,
    Clock, Zap, Layers, Globe, Cpu, Code, Link as LinkIcon,
    Server, AlertOctagon, ChevronDown, ChevronUp
} from 'lucide-react'
import api from '../api/client'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const SEV_COLORS = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#0891b2',
    info: '#6b7280'
}

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

const SOURCE_ICONS = {
    nuclei: { icon: Cpu, color: '#3b82f6', label: 'Nuclei' },
    xray: { icon: Shield, color: '#ec4899', label: 'Xray' },
    manual: { icon: FileText, color: '#6b7280', label: 'Manual' }
}

const SCAN_MODES = {
    fast: { label: 'Fast Scan', icon: Zap, color: 'var(--success-color)' },
    deep: { label: 'Deep Scan', icon: Layers, color: 'var(--warning-color)' },
    comprehensive: { label: 'Comprehensive', icon: Shield, color: 'var(--accent-color)' }
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
    const [sourceFilter, setSourceFilter] = useState('')
    const [groupBy, setGroupBy] = useState('severity')
    const [loading, setLoading] = useState(true)
    const [expandedId, setExpandedId] = useState(null)
    const [activeTab, setActiveTab] = useState('details')

    const loadJob = useCallback(async () => {
        try {
            const data = await api.getScan(jobId)
            setJob(data)
        } catch { }
    }, [jobId])

    const loadFindings = useCallback(async () => {
        try {
            const data = await api.getFindings(jobId, page, sevFilter, owaspFilter, sourceFilter)
            setFindings(data.items)
            setTotalFindings(data.total)
            setTotalPages(data.pages)
        } catch { }
        setLoading(false)
    }, [jobId, page, sevFilter, owaspFilter, sourceFilter])

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
        const key = groupBy === 'severity' ? f.severity : (groupBy === 'source' ? f.source : (f.owasp_category || 'Uncategorized'))
        if (!grouped[key]) grouped[key] = []
        grouped[key].push(f)
    })

    const sortedGroups = groupBy === 'severity'
        ? SEV_ORDER.filter(s => grouped[s])
        : Object.keys(grouped).sort()

    // Format datetime
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

    // Format duration
    const formatDuration = (seconds) => {
        if (!seconds) return '-'
        const hours = Math.floor(seconds / 3600)
        const mins = Math.floor((seconds % 3600) / 60)
        const secs = seconds % 60
        if (hours > 0) return `${hours}h ${mins}m ${secs}s`
        if (mins > 0) return `${mins}m ${secs}s`
        return `${secs}s`
    }

    // Calculate severity counts
    const sevCounts = findings.reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1
        return acc
    }, {})

    if (!job && loading) return <div className="loading-page"><div className="spinner" /></div>

    const modeConfig = SCAN_MODES[job?.scan_mode] || SCAN_MODES.fast

    return (
        <div className="animate-fade">
            <Link to="/scan" className="btn btn-sm btn-secondary" style={{ marginBottom: 'var(--space-4)' }}>
                <ArrowLeft size={14} /> Back to Scans
            </Link>

            {/* Job Info */}
            <div className="card" style={{ marginBottom: 'var(--space-6)' }}>
                <div className="card-header">
                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                        <h3 className="card-title">Scan Details</h3>
                        <span className={`badge badge-${job?.status}`}>{job?.status}</span>
                        <span className="badge" style={{ background: `${modeConfig.color}20`, color: modeConfig.color }}>
                            <modeConfig.icon size={12} style={{ marginRight: 4 }} />
                            {modeConfig.label}
                        </span>
                    </div>
                    <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                        <button className="btn btn-sm btn-secondary" onClick={() => handleExport('json')}>
                            <Download size={12} /> JSON
                        </button>
                        <button className="btn btn-sm btn-secondary" onClick={() => handleExport('csv')}>
                            <Download size={12} /> CSV
                        </button>
                    </div>
                </div>

                {/* Scan Stats Grid */}
                <div style={{ 
                    display: 'grid', 
                    gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', 
                    gap: 'var(--space-4)',
                    marginBottom: 'var(--space-4)'
                }}>
                    <div className="stat-card">
                        <div className="stat-label">Target</div>
                        <div className="stat-value" style={{ fontSize: 'var(--font-size-sm)', wordBreak: 'break-all' }}>
                            <Globe size={14} style={{ marginRight: 4, display: 'inline' }} />
                            {job?.target_url}
                        </div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-label">Created</div>
                        <div className="stat-value" style={{ fontSize: 'var(--font-size-sm)' }}>
                            <Clock size={14} style={{ marginRight: 4, display: 'inline' }} />
                            {formatDateTime(job?.created_at)}
                        </div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-label">Completed</div>
                        <div className="stat-value" style={{ fontSize: 'var(--font-size-sm)' }}>
                            {formatDateTime(job?.finished_at)}
                        </div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-label">Duration</div>
                        <div className="stat-value" style={{ fontSize: 'var(--font-size-sm)' }}>
                            {formatDuration(job?.scan_duration_seconds)}
                        </div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-label">Endpoints</div>
                        <div className="stat-value" style={{ fontSize: 'var(--font-size-sm)' }}>
                            <LinkIcon size={14} style={{ marginRight: 4, display: 'inline' }} />
                            {job?.endpoints_discovered || 0} discovered
                        </div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-label">Total Findings</div>
                        <div className="stat-value" style={{ 
                            fontSize: 'var(--font-size-xl)', 
                            fontWeight: 700,
                            color: job?.findings_count > 0 ? 'var(--accent-color)' : 'var(--success-color)'
                        }}>
                            {job?.findings_count || 0}
                        </div>
                        {(job?.nuclei_findings_count > 0 || job?.xray_findings_count > 0) && (
                            <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', marginTop: 4 }}>
                                {job?.nuclei_findings_count > 0 && <span style={{ color: '#3b82f6' }}>N:{job.nuclei_findings_count} </span>}
                                {job?.xray_findings_count > 0 && <span style={{ color: '#ec4899' }}>X:{job.xray_findings_count}</span>}
                            </div>
                        )}
                    </div>
                </div>

                {/* Severity Summary */}
                {Object.keys(sevCounts).length > 0 && (
                    <div style={{ 
                        display: 'flex', 
                        gap: 'var(--space-3)',
                        flexWrap: 'wrap',
                        padding: 'var(--space-3)',
                        background: 'var(--bg-glass)',
                        borderRadius: 'var(--radius-md)'
                    }}>
                        {SEV_ORDER.filter(s => sevCounts[s]).map(sev => (
                            <div key={sev} style={{ 
                                display: 'flex', 
                                alignItems: 'center', 
                                gap: 6,
                                padding: '4px 12px',
                                background: `${SEV_COLORS[sev]}20`,
                                borderRadius: 'var(--radius-full)',
                                color: SEV_COLORS[sev],
                                fontSize: 'var(--font-size-sm)',
                                fontWeight: 600
                            }}>
                                <AlertOctagon size={12} />
                                {sev}: {sevCounts[sev]}
                            </div>
                        ))}
                    </div>
                )}

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
                        <button className="btn btn-sm btn-secondary" onClick={() => { loadJob(); loadFindings() }}>
                            <RefreshCw size={12} />
                        </button>
                    </div>
                </div>

                <div className="filters-bar" style={{ flexWrap: 'wrap' }}>
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
                    <select className="form-input" value={sourceFilter} onChange={e => { setSourceFilter(e.target.value); setPage(1) }} style={{ maxWidth: 160 }}>
                        <option value="">All Sources</option>
                        <option value="nuclei">Nuclei</option>
                        <option value="xray">Xray</option>
                    </select>
                    <select className="form-input" value={groupBy} onChange={e => setGroupBy(e.target.value)} style={{ maxWidth: 160 }}>
                        <option value="severity">Group by Severity</option>
                        <option value="owasp">Group by OWASP</option>
                        <option value="source">Group by Source</option>
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
                                    {groupBy === 'source' && (
                                        <span style={{ color: 'var(--text-muted)', fontWeight: 400, textTransform: 'none' }}>
                                            {SOURCE_ICONS[group]?.label || group}
                                        </span>
                                    )}
                                    <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>
                                        ({grouped[group].length})
                                    </span>
                                </h4>

                                {grouped[group].map(f => {
                                    const SourceIcon = SOURCE_ICONS[f.source]?.icon || FileText
                                    const sourceColor = SOURCE_ICONS[f.source]?.color || '#6b7280'
                                    const isExpanded = expandedId === f.id
                                    
                                    return (
                                        <div key={f.id} className="finding-card" style={{ 
                                            borderLeft: `3px solid ${SEV_COLORS[f.severity] || '#6b7280'}` 
                                        }}>
                                            <div className="finding-header">
                                                <div style={{ flex: 1 }}>
                                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                                                        <span className="finding-name">{f.name}</span>
                                                        <span 
                                                            className="badge" 
                                                            style={{ 
                                                                background: `${sourceColor}20`, 
                                                                color: sourceColor,
                                                                fontSize: '10px'
                                                            }}
                                                        >
                                                            <SourceIcon size={10} style={{ marginRight: 4 }} />
                                                            {f.source?.toUpperCase()}
                                                        </span>
                                                    </div>
                                                    <div className="finding-meta">
                                                        <span><Tag size={12} />{f.rule_id}</span>
                                                        {f.cwe && <span>CWE: {f.cwe}</span>}
                                                        {f.owasp_category && <span>OWASP: {f.owasp_category}</span>}
                                                        {f.cvss_score && (
                                                            <span style={{ color: SEV_COLORS[f.severity] }}>
                                                                CVSS: {f.cvss_score}
                                                            </span>
                                                        )}
                                                    </div>
                                                    {/* URL and Endpoint Info */}
                                                    {f.matched_url && (
                                                        <div className="finding-meta" style={{ marginTop: 4 }}>
                                                            <span>
                                                                <Globe size={12} />
                                                                {f.matched_url.length > 80 ? f.matched_url.slice(0, 80) + '...' : f.matched_url}
                                                            </span>
                                                            {f.http_method && <span>Method: {f.http_method}</span>}
                                                        </div>
                                                    )}
                                                    {f.endpoint_path && (
                                                        <div className="finding-meta" style={{ marginTop: 2 }}>
                                                            <span><Code size={12} />Endpoint: {f.endpoint_path}</span>
                                                        </div>
                                                    )}
                                                </div>
                                                <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
                                                    <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                                                    <button
                                                        className="btn btn-sm btn-ghost"
                                                        onClick={() => setExpandedId(isExpanded ? null : f.id)}
                                                    >
                                                        {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                                                    </button>
                                                </div>
                                            </div>

                                            {isExpanded && (
                                                <div className="animate-fade" style={{ marginTop: 'var(--space-4)' }}>
                                                    {/* Tabs */}
                                                    <div style={{ 
                                                        display: 'flex', 
                                                        gap: 'var(--space-2)',
                                                        borderBottom: '1px solid var(--border-color)',
                                                        marginBottom: 'var(--space-3)'
                                                    }}>
                                                        {['details', 'request', 'response'].map(tab => (
                                                            <button
                                                                key={tab}
                                                                onClick={() => setActiveTab(tab)}
                                                                style={{
                                                                    padding: '8px 16px',
                                                                    border: 'none',
                                                                    background: 'none',
                                                                    color: activeTab === tab ? 'var(--accent-color)' : 'var(--text-muted)',
                                                                    borderBottom: activeTab === tab ? '2px solid var(--accent-color)' : 'none',
                                                                    marginBottom: -1,
                                                                    cursor: 'pointer',
                                                                    textTransform: 'capitalize'
                                                                }}
                                                            >
                                                                {tab}
                                                            </button>
                                                        ))}
                                                    </div>

                                                    {activeTab === 'details' && (
                                                        <>
                                                            {f.description && (
                                                                <div style={{ marginBottom: 'var(--space-3)' }}>
                                                                    <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', marginBottom: 4, fontWeight: 600 }}>
                                                                        Description
                                                                    </div>
                                                                    <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                                                                        {f.description}
                                                                    </div>
                                                                </div>
                                                            )}

                                                            {/* Parameter Info */}
                                                            {f.vulnerable_parameter && (
                                                                <div style={{ 
                                                                    marginBottom: 'var(--space-3)',
                                                                    padding: 'var(--space-3)',
                                                                    background: 'rgba(239, 68, 68, 0.1)',
                                                                    borderRadius: 'var(--radius-md)',
                                                                    border: '1px solid rgba(239, 68, 68, 0.2)'
                                                                }}>
                                                                    <div style={{ fontSize: 'var(--font-size-xs)', color: '#ef4444', marginBottom: 4, fontWeight: 600 }}>
                                                                        <AlertTriangle size={12} style={{ display: 'inline', marginRight: 4 }} />
                                                                        Vulnerable Parameter
                                                                    </div>
                                                                    <div style={{ fontSize: 'var(--font-size-sm)' }}>
                                                                        <code style={{ background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: 4 }}>
                                                                            {f.vulnerable_parameter}
                                                                        </code>
                                                                        {f.parameter_location && (
                                                                            <span style={{ marginLeft: 8, color: 'var(--text-muted)' }}>
                                                                                Location: {f.parameter_location}
                                                                            </span>
                                                                        )}
                                                                    </div>
                                                                </div>
                                                            )}

                                                            {f.evidence && (
                                                                <div style={{ marginBottom: 'var(--space-3)' }}>
                                                                    <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', marginBottom: 4, fontWeight: 600 }}>
                                                                        Evidence
                                                                    </div>
                                                                    <div className="finding-evidence">{f.evidence}</div>
                                                                </div>
                                                            )}

                                                            {f.remediation && (
                                                                <div style={{ 
                                                                    marginBottom: 'var(--space-3)',
                                                                    padding: 'var(--space-3)',
                                                                    background: 'rgba(34, 197, 94, 0.1)',
                                                                    borderRadius: 'var(--radius-md)',
                                                                    border: '1px solid rgba(34, 197, 94, 0.2)'
                                                                }}>
                                                                    <div style={{ fontSize: 'var(--font-size-xs)', color: '#22c55e', marginBottom: 4, fontWeight: 600 }}>
                                                                        <Shield size={12} style={{ display: 'inline', marginRight: 4 }} />
                                                                        Remediation
                                                                    </div>
                                                                    <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)' }}>
                                                                        {f.remediation}
                                                                    </div>
                                                                </div>
                                                            )}

                                                            {f.references && (
                                                                <div style={{ marginBottom: 'var(--space-3)' }}>
                                                                    <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', marginBottom: 4, fontWeight: 600 }}>
                                                                        References
                                                                    </div>
                                                                    <div style={{ fontSize: 'var(--font-size-sm)' }}>
                                                                        {JSON.parse(f.references || '[]').map((ref, idx) => (
                                                                            <div key={idx}>
                                                                                <a href={ref} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-color)' }}>
                                                                                    <ExternalLink size={10} style={{ display: 'inline', marginRight: 4 }} />
                                                                                    {ref}
                                                                                </a>
                                                                            </div>
                                                                        ))}
                                                                    </div>
                                                                </div>
                                                            )}
                                                        </>
                                                    )}

                                                    {activeTab === 'request' && f.request_data && (
                                                        <div>
                                                            <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', marginBottom: 4, fontWeight: 600 }}>
                                                                HTTP Request
                                                            </div>
                                                            <pre style={{ 
                                                                background: 'var(--bg-glass)', 
                                                                padding: 'var(--space-3)',
                                                                borderRadius: 'var(--radius-md)',
                                                                fontSize: 'var(--font-size-xs)',
                                                                overflow: 'auto',
                                                                maxHeight: 400,
                                                                color: 'var(--text-secondary)'
                                                            }}>
                                                                <code>{f.request_data}</code>
                                                            </pre>
                                                        </div>
                                                    )}

                                                    {activeTab === 'response' && f.response_data && (
                                                        <div>
                                                            <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', marginBottom: 4, fontWeight: 600 }}>
                                                                HTTP Response
                                                            </div>
                                                            <pre style={{ 
                                                                background: 'var(--bg-glass)', 
                                                                padding: 'var(--space-3)',
                                                                borderRadius: 'var(--radius-md)',
                                                                fontSize: 'var(--font-size-xs)',
                                                                overflow: 'auto',
                                                                maxHeight: 400,
                                                                color: 'var(--text-secondary)'
                                                            }}>
                                                                <code>{f.response_data}</code>
                                                            </pre>
                                                        </div>
                                                    )}

                                                    {/* Status Actions */}
                                                    <div style={{ marginTop: 'var(--space-4)', display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
                                                        <span style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)' }}>
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
                                    )
                                })}
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
