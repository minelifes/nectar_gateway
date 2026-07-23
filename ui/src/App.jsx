import { useCallback, useEffect, useState } from 'react'
import {
  AppBar, Toolbar, Typography, Container, Paper, Table, TableBody,
  TableCell, TableContainer, TableHead, TableRow, IconButton, Button,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField, Stack,
  Snackbar, Alert, Chip, Tooltip, ToggleButton, ToggleButtonGroup,
  FormControlLabel, Switch, Divider
} from '@mui/material'
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Dns as DnsIcon,
  Logout as LogoutIcon,
  SwapHoriz as SwapHorizIcon,
  Folder as FolderIcon,
  Lock as LockIcon,
  EnhancedEncryption as EnhancedEncryptionIcon,
  UploadFile as UploadFileIcon
} from '@mui/icons-material'
import { CircularProgress } from '@mui/material'
import Login from './Login'
import ImportNginx from './ImportNginx'

const empty = {
  domain: '', mode: 'proxy', target_ip: '', target_port: 80, static_dir: '',
  cert_file: '', key_file: '', force_ssl: false
}

export default function App() {
  const [authed, setAuthed] = useState(null) // null = checking
  const [routes, setRoutes] = useState([])
  const [dialog, setDialog] = useState(null) // null | {mode:'add'|'edit', route}
  const [importOpen, setImportOpen] = useState(false)
  const [error, setError] = useState('')
  const [ok, setOk] = useState('')
  const [certBusy, setCertBusy] = useState(null) // route id being issued

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/routes')
      if (res.status === 401) {
        setAuthed(false)
        return
      }
      if (!res.ok) throw new Error(await res.text())
      setRoutes(await res.json())
    } catch (e) {
      setError('Failed to load routes: ' + e.message)
    }
  }, [])

  useEffect(() => {
    fetch('/api/me').then((res) => {
      setAuthed(res.ok)
      if (res.ok) load()
    }).catch(() => setAuthed(false))
  }, [load])

  const logout = async () => {
    await fetch('/api/logout', { method: 'POST' })
    setAuthed(false)
    setRoutes([])
  }

  if (authed === null) return null
  if (!authed) {
    return <Login onLogin={() => { setAuthed(true); load() }} />
  }

  const save = async (thenCert = false) => {
    const { mode, route } = dialog
    const url = mode === 'add' ? '/api/routes' : `/api/routes/${route.id}`
    try {
      const res = await fetch(url, {
        method: mode === 'add' ? 'POST' : 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...route, target_port: Number(route.target_port) || 80 })
      })
      const body = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(body.error || res.statusText)
      setDialog(null)
      load()
      if (thenCert && body.id) issueCert(body)
    } catch (e) {
      setError('Save failed: ' + e.message)
    }
  }

  const remove = async (r) => {
    if (!confirm(`Delete route for ${r.domain}?`)) return
    const res = await fetch(`/api/routes/${r.id}`, { method: 'DELETE' })
    if (!res.ok) setError('Delete failed')
    load()
  }

  const issueCert = async (r) => {
    setCertBusy(r.id)
    try {
      const res = await fetch(`/api/routes/${r.id}/cert`, { method: 'POST' })
      const body = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(body.error || res.statusText)
      setOk(`Certificate issued for ${r.domain}`)
      load()
    } catch (e) {
      setError('Certificate failed: ' + e.message)
    } finally {
      setCertBusy(null)
    }
  }

  const set = (field) => (e) =>
    setDialog((d) => ({ ...d, route: { ...d.route, [field]: e.target.value } }))

  return (
    <>
      <AppBar position="static">
        <Toolbar>
          <DnsIcon sx={{ mr: 1.5 }} />
          <Typography variant="h6" sx={{ flexGrow: 1 }}>Nectar Gateway</Typography>
          <Button color="inherit" startIcon={<AddIcon />}
            onClick={() => setDialog({ mode: 'add', route: { ...empty } })}>
            Add domain
          </Button>
          <Button color="inherit" startIcon={<UploadFileIcon />} sx={{ ml: 1 }}
            onClick={() => setImportOpen(true)}>
            Import nginx
          </Button>
          <Tooltip title="Sign out">
            <IconButton color="inherit" onClick={logout} sx={{ ml: 1 }}>
              <LogoutIcon />
            </IconButton>
          </Tooltip>
        </Toolbar>
      </AppBar>

      <Container maxWidth="md" sx={{ mt: 4 }}>
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Domain</TableCell>
                <TableCell>Target</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {routes.length === 0 && (
                <TableRow>
                  <TableCell colSpan={3} align="center" sx={{ py: 6, color: 'text.secondary' }}>
                    No domains configured. Requests to unknown domains return 410 Gone.
                  </TableCell>
                </TableRow>
              )}
              {routes.map((r) => (
                <TableRow key={r.id} hover>
                  <TableCell>
                    {r.domain}
                    {r.cert_file && r.key_file && (
                      <Tooltip title={r.force_ssl ? 'HTTPS (forced)' : 'HTTPS enabled'}>
                        <LockIcon sx={{ fontSize: 14, ml: 0.75, verticalAlign: 'middle', color: 'success.main' }} />
                      </Tooltip>
                    )}
                  </TableCell>
                  <TableCell>
                    {r.mode === 'static' ? (
                      <Chip size="small" color="secondary" icon={<FolderIcon />} label={r.static_dir} />
                    ) : (
                      <Chip size="small" icon={<SwapHorizIcon />} label={`${r.target_ip}:${r.target_port}`} />
                    )}
                  </TableCell>
                  <TableCell align="right">
                    {!(r.cert_file && r.key_file) && (
                      <Tooltip title="Get Let's Encrypt certificate">
                        <span>
                          <IconButton color="success" disabled={certBusy !== null}
                            onClick={() => issueCert(r)}>
                            {certBusy === r.id
                              ? <CircularProgress size={18} color="inherit" />
                              : <EnhancedEncryptionIcon fontSize="small" />}
                          </IconButton>
                        </span>
                      </Tooltip>
                    )}
                    <Tooltip title="Edit">
                      <IconButton onClick={() => setDialog({ mode: 'edit', route: { ...r } })}>
                        <EditIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete">
                      <IconButton color="error" onClick={() => remove(r)}>
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Container>

      <Dialog open={!!dialog} onClose={() => setDialog(null)} fullWidth maxWidth="xs">
        <DialogTitle>{dialog?.mode === 'add' ? 'Add domain' : 'Edit domain'}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="Domain" placeholder="example.com" fullWidth autoFocus
              value={dialog?.route.domain ?? ''} onChange={set('domain')} />
            <ToggleButtonGroup exclusive fullWidth color="primary" size="small"
              value={dialog?.route.mode ?? 'proxy'}
              onChange={(_, mode) => mode && setDialog((d) => ({ ...d, route: { ...d.route, mode } }))}>
              <ToggleButton value="proxy">Proxy</ToggleButton>
              <ToggleButton value="static">Static files</ToggleButton>
            </ToggleButtonGroup>
            {(dialog?.route.mode ?? 'proxy') === 'proxy' ? (
              <>
                <TextField label="Target IP" placeholder="192.168.1.10" fullWidth
                  value={dialog?.route.target_ip ?? ''} onChange={set('target_ip')} />
                <TextField label="Target port" type="number" fullWidth
                  value={dialog?.route.target_port ?? 80} onChange={set('target_port')} />
              </>
            ) : (
              <TextField label="Static directory" placeholder="/var/www/example.com" fullWidth
                helperText="Serves files from this folder (index.html for /)"
                value={dialog?.route.static_dir ?? ''} onChange={set('static_dir')} />
            )}
            <Divider>
              <Typography variant="caption" color="text.secondary">SSL (optional)</Typography>
            </Divider>
            <Button variant="outlined" color="success" startIcon={<EnhancedEncryptionIcon />}
              disabled={!dialog?.route.domain ||
                (dialog?.route.mode === 'static' ? !dialog?.route.static_dir : !dialog?.route.target_ip)}
              onClick={() => save(true)}>
              Save & get Let's Encrypt certificate
            </Button>
            <Typography variant="caption" color="text.secondary" sx={{ textAlign: 'center' }}>
              — or set certificate paths manually —
            </Typography>
            <TextField label="Certificate file" placeholder="/etc/letsencrypt/live/example.com/fullchain.pem"
              fullWidth value={dialog?.route.cert_file ?? ''} onChange={set('cert_file')} />
            <TextField label="Private key file" placeholder="/etc/letsencrypt/live/example.com/privkey.pem"
              fullWidth value={dialog?.route.key_file ?? ''} onChange={set('key_file')} />
            <FormControlLabel
              control={<Switch checked={!!dialog?.route.force_ssl}
                disabled={!dialog?.route.cert_file || !dialog?.route.key_file}
                onChange={(e) => setDialog((d) => ({ ...d, route: { ...d.route, force_ssl: e.target.checked } }))} />}
              label="Redirect HTTP → HTTPS" />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialog(null)}>Cancel</Button>
          <Button variant="contained" onClick={() => save()}
            disabled={!dialog?.route.domain ||
              (dialog?.route.mode === 'static' ? !dialog?.route.static_dir : !dialog?.route.target_ip)}>
            Save
          </Button>
        </DialogActions>
      </Dialog>

      <ImportNginx open={importOpen} onClose={() => setImportOpen(false)}
        onImported={() => load()} />

      <Snackbar open={!!error} autoHideDuration={5000} onClose={() => setError('')}>
        <Alert severity="error" onClose={() => setError('')}>{error}</Alert>
      </Snackbar>
      <Snackbar open={!!ok} autoHideDuration={4000} onClose={() => setOk('')}>
        <Alert severity="success" onClose={() => setOk('')}>{ok}</Alert>
      </Snackbar>
    </>
  )
}
