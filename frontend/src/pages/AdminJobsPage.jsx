import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { FileText, ExternalLink, Search } from 'lucide-react'
import api from '../api/client'

export default function AdminJobsPage() {
    const [jobs, setJobs] = useState([])
    const [page, setPage] = useState(1)
    const [totalPages, setTotalPages] = useState(1)
    const [statusFilter, setStatusFilter] = useState('')
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const load = async () => {
            try {
                const data = await api.listAllJobs(page, statusFilter)
                setJobs(data.items)
                setTotalPages(data.pages)
            } catch { }
            setLoading(false)
        }
        load()
    }, [page, statusFilter])

    return (
        <div className="animate-fade">
            <div className="page-header">
                <div>
                    <h1 className="page-title">All Scan Jobs</h1>
                    <p className="page-subtitle">View scan history across all users</p>
                </div>
            </div>

            <div className="card">
                <div className="filters-bar">
                    <select className="form-input" value={statusFilter}
                        onChange={e => { setStatusFilter(e.target.value); setPage(1) }} style={{ maxWidth: 200 }}>
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
                        <FileText size={48} />
                        <h3>No jobs found</h3>
                    </div>
                ) : (
                    <>
                        <div className="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>User</th>
                                        <th>Target</th>
                                        <th>Status</th>
                                        <th>Findings</th>
                                        <th>Created</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {jobs.map(job => (
                                        <tr key={job.id}>
                                            <td>#{job.id}</td>
                                            <td>#{job.user_id}</td>
                                            <td style={{ maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                                {job.target_url}
                                            </td>
                                            <td><span className={`badge badge-${job.status}`}>{job.status}</span></td>
                                            <td>{job.findings_count}</td>
                                            <td>{new Date(job.created_at).toLocaleString()}</td>
                                            <td>
                                                <Link to={`/scan/${job.id}`} className="btn btn-sm btn-secondary">
                                                    <ExternalLink size={12} /> View
                                                </Link>
                                            </td>
                                        </tr>
                                    ))}
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
