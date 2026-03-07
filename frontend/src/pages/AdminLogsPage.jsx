import { useState, useEffect } from 'react'
import { FileText, Search } from 'lucide-react'
import api from '../api/client'

export default function AdminLogsPage() {
    const [logs, setLogs] = useState([])
    const [page, setPage] = useState(1)
    const [totalPages, setTotalPages] = useState(1)
    const [actionFilter, setActionFilter] = useState('')
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const load = async () => {
            try {
                const data = await api.listLogs(page, actionFilter)
                setLogs(data.items)
                setTotalPages(data.pages)
            } catch { }
            setLoading(false)
        }
        load()
    }, [page, actionFilter])

    return (
        <div className="animate-fade">
            <div className="page-header">
                <div>
                    <h1 className="page-title">Audit Logs</h1>
                    <p className="page-subtitle">Track all system activities</p>
                </div>
            </div>

            <div className="card">
                <div className="filters-bar">
                    <select className="form-input" value={actionFilter} onChange={e => { setActionFilter(e.target.value); setPage(1) }} style={{ maxWidth: 200 }}>
                        <option value="">All Actions</option>
                        <option value="login">Login</option>
                        <option value="logout">Logout</option>
                        <option value="scan">Scan</option>
                        <option value="user">User Management</option>
                        <option value="finding">Findings</option>
                    </select>
                </div>

                {loading ? (
                    <div className="empty-state"><div className="spinner" /></div>
                ) : logs.length === 0 ? (
                    <div className="empty-state">
                        <FileText size={48} />
                        <h3>No logs found</h3>
                    </div>
                ) : (
                    <>
                        <div className="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Timestamp</th>
                                        <th>User</th>
                                        <th>Action</th>
                                        <th>Details</th>
                                        <th>IP</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {logs.map(log => (
                                        <tr key={log.id}>
                                            <td>{new Date(log.timestamp).toLocaleString()}</td>
                                            <td>{log.username || '-'}</td>
                                            <td><span className="badge badge-default">{log.action}</span></td>
                                            <td style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                                {log.details || '-'}
                                            </td>
                                            <td>{log.ip_address || '-'}</td>
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
