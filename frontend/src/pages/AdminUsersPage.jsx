import { useState, useEffect, useCallback } from 'react'
import { Users, Plus, Pencil, Trash2, Search, X } from 'lucide-react'
import api from '../api/client'

export default function AdminUsersPage() {
    const [users, setUsers] = useState([])
    const [page, setPage] = useState(1)
    const [totalPages, setTotalPages] = useState(1)
    const [search, setSearch] = useState('')
    const [loading, setLoading] = useState(true)
    const [modalOpen, setModalOpen] = useState(false)
    const [editUser, setEditUser] = useState(null)
    const [form, setForm] = useState({ username: '', email: '', password: '', role: 'user' })
    const [formError, setFormError] = useState('')
    const [saving, setSaving] = useState(false)

    const loadUsers = useCallback(async () => {
        try {
            const data = await api.listUsers(page, search)
            setUsers(data.items)
            setTotalPages(data.pages)
        } catch { }
        setLoading(false)
    }, [page, search])

    useEffect(() => { loadUsers() }, [loadUsers])

    const openCreate = () => {
        setEditUser(null)
        setForm({ username: '', email: '', password: '', role: 'user' })
        setFormError('')
        setModalOpen(true)
    }

    const openEdit = (user) => {
        setEditUser(user)
        setForm({ username: user.username, email: user.email, password: '', role: user.role })
        setFormError('')
        setModalOpen(true)
    }

    const handleSubmit = async (e) => {
        e.preventDefault()
        setFormError('')
        setSaving(true)
        try {
            if (editUser) {
                const data = { ...form }
                if (!data.password) delete data.password
                await api.updateUser(editUser.id, data)
            } else {
                await api.createUser(form)
            }
            setModalOpen(false)
            loadUsers()
        } catch (err) {
            setFormError(err.message)
        } finally {
            setSaving(false)
        }
    }

    const handleDelete = async (user) => {
        if (!confirm(`Delete user "${user.username}"? This cannot be undone.`)) return
        try {
            await api.deleteUser(user.id)
            loadUsers()
        } catch (err) {
            alert(err.message)
        }
    }

    return (
        <div className="animate-fade">
            <div className="page-header">
                <div>
                    <h1 className="page-title">User Management</h1>
                    <p className="page-subtitle">Create and manage user accounts</p>
                </div>
                <button className="btn btn-primary" onClick={openCreate}>
                    <Plus size={16} /> New User
                </button>
            </div>

            <div className="card">
                <div className="filters-bar">
                    <div className="search-input" style={{ position: 'relative' }}>
                        <Search size={16} style={{
                            position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)',
                            color: 'var(--text-muted)',
                        }} />
                        <input
                            className="form-input"
                            placeholder="Search users..."
                            value={search}
                            onChange={e => { setSearch(e.target.value); setPage(1) }}
                            style={{ paddingLeft: 36 }}
                        />
                    </div>
                </div>

                {loading ? (
                    <div className="empty-state"><div className="spinner" /></div>
                ) : (
                    <>
                        <div className="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Username</th>
                                        <th>Email</th>
                                        <th>Role</th>
                                        <th>Status</th>
                                        <th>Created</th>
                                        <th>Last Login</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {users.map(u => (
                                        <tr key={u.id}>
                                            <td style={{ fontWeight: 500 }}>{u.username}</td>
                                            <td>{u.email}</td>
                                            <td><span className={`badge ${u.role === 'admin' ? 'badge-critical' : 'badge-info'}`}>{u.role}</span></td>
                                            <td><span className={`badge ${u.is_active ? 'badge-success' : 'badge-danger'}`}>{u.is_active ? 'Active' : 'Inactive'}</span></td>
                                            <td>{new Date(u.created_at).toLocaleDateString()}</td>
                                            <td>{u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}</td>
                                            <td>
                                                <div className="table-actions">
                                                    <button className="btn btn-sm btn-secondary" onClick={() => openEdit(u)}>
                                                        <Pencil size={12} />
                                                    </button>
                                                    <button className="btn btn-sm btn-danger" onClick={() => handleDelete(u)}>
                                                        <Trash2 size={12} />
                                                    </button>
                                                </div>
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

            {/* User Modal */}
            {modalOpen && (
                <div className="modal-overlay" onClick={() => setModalOpen(false)}>
                    <div className="modal" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3 className="modal-title">{editUser ? 'Edit User' : 'Create User'}</h3>
                            <button className="btn-ghost" onClick={() => setModalOpen(false)}><X size={18} /></button>
                        </div>

                        {formError && <div className="alert alert-error">{formError}</div>}

                        <form onSubmit={handleSubmit}>
                            <div className="form-group">
                                <label className="form-label">Username</label>
                                <input className="form-input" value={form.username}
                                    onChange={e => setForm({ ...form, username: e.target.value })} required />
                            </div>
                            <div className="form-group">
                                <label className="form-label">Email</label>
                                <input className="form-input" type="email" value={form.email}
                                    onChange={e => setForm({ ...form, email: e.target.value })} required />
                            </div>
                            <div className="form-group">
                                <label className="form-label">Password {editUser && '(leave empty to keep current)'}</label>
                                <input className="form-input" type="password" value={form.password}
                                    onChange={e => setForm({ ...form, password: e.target.value })}
                                    required={!editUser} minLength={8} />
                            </div>
                            <div className="form-group">
                                <label className="form-label">Role</label>
                                <select className="form-input" value={form.role}
                                    onChange={e => setForm({ ...form, role: e.target.value })}>
                                    <option value="user">User</option>
                                    <option value="admin">Admin</option>
                                </select>
                            </div>
                            <div className="modal-footer">
                                <button type="button" className="btn btn-secondary" onClick={() => setModalOpen(false)}>Cancel</button>
                                <button type="submit" className="btn btn-primary" disabled={saving}>
                                    {saving ? <><div className="spinner" /> Saving...</> : (editUser ? 'Update' : 'Create')}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    )
}
