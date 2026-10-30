import { useCallback, useEffect, useRef, useState } from 'react'
import {
  AppBar, Toolbar, Typography, Container, Paper, Table, TableBody,
  TableCell, TableContainer, TableHead, TableRow, IconButton, Button,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField, Stack,
  Snackbar, Alert, Chip, Tooltip, ToggleButton, ToggleButtonGroup,
  FormControlLabel, Switch, Divider, Box, InputAdornment, Tabs, Tab,
  Select, MenuItem, FormControl, InputLabel
} from '@mui/material'
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Logout as LogoutIcon,
  SwapHoriz as SwapHorizIcon,
  Folder as FolderIcon,
  Lock as LockIcon,
  ExpandMore as ExpandMoreIcon,
  ChevronRight as ChevronRightIcon,
  Language as LanguageIcon,
  EnhancedEncryption as EnhancedEncryptionIcon,
  UploadFile as UploadFileIcon,
  VerifiedUser as VerifiedUserIcon,
  Settings as SettingsIcon,
  Construction as ConstructionIcon,
  Key as KeyIcon,
  CallMade as CallMadeIcon
} from '@mui/icons-material'
import { CircularProgress } from '@mui/material'
import WebOptions, { formToWeb, webToForm } from './WebOptions.jsx'
import {
  GppBad as GppBadIcon,
  Dns as DnsListIcon,
  NotificationsActive as NotificationsActiveIcon,
  NotificationsOff as NotificationsOffIcon
} from '@mui/icons-material'
import Login from './Login'
import ImportNginx from './ImportNginx'
import BlockedIps from './BlockedIps'
import Certificates from './Certificates'
import Settings from './Settings'

// abc.domainA.com -> domainA.com; domainA.com -> domainA.com
const parentOf = (d) => {
  const parts = d.split('.')
  return parts.length <= 2 ? d : parts.slice(-2).join('.')
}

const empty = {
  domain: '', path_prefix: '/', mode: 'proxy', target_ip: '', target_port: 80, target_https: false,
  rate_limit: 0, static_dir: '', cert_file: '', key_file: '', force_ssl: false,
  hc_enabled: false, hc_path: '/', hc_interval: 30, hc_type: 'status', hc_expect: '',
  acme: false, maintenance: false, backend_protocol: 'http1', timeout_seconds: 0, max_body_mb: 0,
  redirect_url: '', redirect_code: 301
}

// the dialog edits basic-auth users as a list; an empty password keeps the stored one
const withAuth = (r) => ({
  ...r, auth: (r.auth_usernames || []).map((user) => ({ user, password: '' })), authEdited: false,
  webForm: webToForm(r.web), webEdited: false
})

const hasCert = (r) => (r.cert_file && r.key_file) || r.cert_not_after > 0

const targetReady = (r) => r && r.domain && (
  r.mode === 'static' ? !!r.static_dir : r.mode === 'redirect' ? !!r.redirect_url : !!r.target_ip)

const hcExpectHelp = {
  status: 'Expected status code, empty = any non-error (2xx/3xx)',
  contains: 'Response body must contain this text',
  json: 'field=value; other=value — all must match. Alternatives with |: status=ok|degraded; checks.db=up'
}

function HealthDot({ status, enabled }) {
  const color = !enabled ? 'grey.600'
    : status?.up === true ? 'success.main'
    : status?.up === false ? 'error.main'
    : 'grey.500'
  const title = !enabled ? 'Health check disabled'
    : status?.up === true ? 'Backend healthy'
    : status?.up === false ? `Backend DOWN: ${status.last_error}`
    : 'Waiting for first check'
  return (
    <Tooltip title={title}>
      <Box component="span" sx={{
        display: 'inline-block', width: 10, height: 10, borderRadius: '50%',
        bgcolor: color, mr: 1, flexShrink: 0
      }} />
    </Tooltip>
  )
}

export default function App() {
  const [authed, setAuthed] = useState(null) // null = checking
  const [routes, setRoutes] = useState([])
  const [dialog, setDialog] = useState(null) // null | {mode:'add'|'edit', route}
  const [importOpen, setImportOpen] = useState(false)
  const [error, setError] = useState('')
  const [ok, setOk] = useState('')
  const [certBusy, setCertBusy] = useState(null) // route id being issued
  const [collapsed, setCollapsed] = useState({}) // parent domain -> bool
  const [view, setView] = useState('routes') // 'routes' | 'blocked' | 'certificates' | 'settings'
  const [dnsReady, setDnsReady] = useState(false)
  const [healthMap, setHealthMap] = useState({})
  const [notifOn, setNotifOn] = useState(
    () => typeof Notification !== 'undefined' && Notification.permission === 'granted'
      && localStorage.getItem('nectar_notif') === '1'
  )
  const prevHealth = useRef(null)
  const routesRef = useRef([])
  useEffect(() => { routesRef.current = routes }, [routes])

  const toggleNotif = async () => {
    if (typeof Notification === 'undefined') {
      setError('Notifications need HTTPS (or localhost) — open the admin UI over HTTPS')
      return
    }
    if (notifOn) {
      localStorage.setItem('nectar_notif', '0')
      setNotifOn(false)
      return
    }
    const perm = await Notification.requestPermission()
    if (perm === 'granted') {
      localStorage.setItem('nectar_notif', '1')
      setNotifOn(true)
      new Notification('Nectar Gateway', { body: 'Browser notifications enabled — keep this tab open to receive alerts' })
    } else {
      setError('Notification permission denied — allow it in the browser site settings')
    }
  }

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

  const onSettings = useCallback((v) => setDnsReady(!!v?.dns_provider && !!v?.dns_token_set), [])
  useEffect(() => {
    if (!authed) return
    fetch('/api/settings').then((res) => res.ok ? res.json() : null).then(onSettings).catch(() => {})
  }, [authed, onSettings])

  useEffect(() => {
    if (!authed) return
    const notify = (title, body) => {
      if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return
      if (localStorage.getItem('nectar_notif') !== '1') return
      try { new Notification(title, { body, requireInteraction: true }) } catch { /* ignore */ }
    }
    const poll = () => fetch('/api/health')
      .then((res) => res.ok ? res.json() : {})
      .then((data) => {
        const prev = prevHealth.current
        if (prev) {
          for (const [id, cur] of Object.entries(data)) {
            const was = prev[id]
            const domain = routesRef.current.find((r) => String(r.id) === id)?.domain || `route #${id}`
            if (cur.up === false && was?.up !== false) {
              notify(`🔴 ${domain} is DOWN`, cur.last_error || 'health check failed')
            } else if (cur.up === true && was?.up === false) {
              notify(`🟢 ${domain} recovered`, 'backend is healthy again')
            }
          }
        }
        prevHealth.current = data
        setHealthMap(data)
      })
      .catch(() => {})
    poll()
    const t = setInterval(poll, 15000)
    return () => clearInterval(t)
  }, [authed])

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
    const { auth, authEdited, webForm, webEdited, web: _w, auth_usernames: _u, auth_fingerprint: _f, covered_by: _c, covered_until: _cu, ...rest } = route
    const payload = {
      ...rest,
      target_port: Number(route.target_port) || 80,
      rate_limit: Number(route.rate_limit) || 0,
      hc_interval: Number(route.hc_interval) || 30,
      timeout_seconds: Number(route.timeout_seconds) || 0,
      max_body_mb: Number(route.max_body_mb) || 0,
      redirect_code: Number(route.redirect_code) || 301
    }
    if (webEdited || mode === 'add') payload.web = formToWeb(webForm)
    if (authEdited) payload.basic_auth_users = auth.filter((u) => u.user.trim()).map((u) => ({ user: u.user.trim(), password: u.password }))
    try {
      const res = await fetch(url, {
        method: mode === 'add' ? 'POST' : 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
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
  const setBool = (field) => (e) =>
    setDialog((d) => ({ ...d, route: { ...d.route, [field]: e.target.checked } }))
  const setWeb = (webForm) => setDialog((d) => ({ ...d, route: { ...d.route, webForm, webEdited: true } }))
  const setAuth = (fn) => setDialog((d) => ({ ...d, route: { ...d.route, auth: fn(d.route.auth), authEdited: true } }))

  // group routes by parent domain, groups and members sorted alphabetically
  const groups = routes.reduce((acc, r) => {
    const p = parentOf(r.domain)
    ;(acc[p] = acc[p] || []).push(r)
    return acc
  }, {})
  const parents = Object.keys(groups).sort()

  return (
    <>
      <AppBar position="static">
        <Toolbar>
          <Box component="img" src="/icon-192.png" alt="Nectar"
            sx={{ width: 32, height: 32, borderRadius: '8px', mr: 1.5 }} />
          <Typography variant="h6" sx={{ flexGrow: 1 }}>Nectar Gateway</Typography>
          {view === 'routes' && (
            <>
              <Button color="inherit" startIcon={<AddIcon />}
                onClick={() => setDialog({ mode: 'add', route: withAuth(empty) })}>
                Add domain
              </Button>
              <Button color="inherit" startIcon={<UploadFileIcon />} sx={{ ml: 1 }}
                onClick={() => setImportOpen(true)}>
                Import nginx
              </Button>
            </>
          )}
          <Tooltip title={notifOn ? 'Browser notifications on (works while this tab is open)' : 'Enable browser notifications for backend health'}>
            <IconButton color="inherit" onClick={toggleNotif} sx={{ ml: 1 }}>
              {notifOn ? <NotificationsActiveIcon /> : <NotificationsOffIcon />}
            </IconButton>
          </Tooltip>
          <Tooltip title="Sign out">
            <IconButton color="inherit" onClick={logout} sx={{ ml: 1 }}>
              <LogoutIcon />
            </IconButton>
          </Tooltip>
        </Toolbar>
        <Tabs value={view} onChange={(_, v) => setView(v)}
          textColor="inherit" indicatorColor="secondary" sx={{ px: 2 }}>
          <Tab value="routes" label="Domains" icon={<DnsListIcon />} iconPosition="start" sx={{ minHeight: 48 }} />
          <Tab value="certificates" label="Certificates" icon={<VerifiedUserIcon />} iconPosition="start" sx={{ minHeight: 48 }} />
          <Tab value="blocked" label="Blocked IPs" icon={<GppBadIcon />} iconPosition="start" sx={{ minHeight: 48 }} />
          <Tab value="settings" label="Settings" icon={<SettingsIcon />} iconPosition="start" sx={{ minHeight: 48 }} />
        </Tabs>
      </AppBar>

      {view === 'blocked' && <BlockedIps onError={setError} />}
      {view === 'certificates' && <Certificates onError={setError} onOk={setOk} dnsReady={dnsReady} />}
      {view === 'settings' && <Settings onError={setError} onOk={setOk} onChange={onSettings} />}

      {view === 'routes' && (
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
              {parents.map((parent) => [
                <TableRow key={parent} hover
                  onClick={() => setCollapsed((c) => ({ ...c, [parent]: !c[parent] }))}
                  sx={{ cursor: 'pointer', bgcolor: 'action.hover' }}>
                  <TableCell colSpan={3} sx={{ py: 0.75 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      {collapsed[parent]
                        ? <ChevronRightIcon fontSize="small" />
                        : <ExpandMoreIcon fontSize="small" />}
                      <LanguageIcon fontSize="small" color="primary" />
                      <Typography variant="subtitle2">{parent}</Typography>
                      <Chip size="small" variant="outlined"
                        label={`${groups[parent].length} domain${groups[parent].length > 1 ? 's' : ''}`}
                        sx={{ height: 20 }} />
                      <Box sx={{ flexGrow: 1 }} />
                      <Tooltip title={`Add subdomain of ${parent}`}>
                        <IconButton size="small" color="primary"
                          onClick={(e) => {
                            e.stopPropagation()
                            setDialog({ mode: 'add', suffix: parent, route: withAuth(empty) })
                          }}>
                          <AddIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </TableCell>
                </TableRow>,
                ...(collapsed[parent] ? [] : groups[parent].map((r) => (
                <TableRow key={r.id} hover>
                  <TableCell sx={{ pl: 6 }}>
                    {r.mode === 'proxy' && <HealthDot status={healthMap[String(r.id)]} enabled={r.hc_enabled} />}
                    {r.domain}
                    {r.path_prefix && r.path_prefix !== '/' && (
                      <Box component="span" sx={{ color: 'text.secondary', fontFamily: 'monospace' }}>{r.path_prefix}</Box>
                    )}
                    {r.managed_by && (
                      <Tooltip title={`Managed by ${r.managed_by} — change it there`}>
                        <Chip size="small" variant="outlined" label={r.managed_by} sx={{ ml: 0.75, height: 20 }} />
                      </Tooltip>
                    )}
                    {r.maintenance && <Chip size="small" color="warning" icon={<ConstructionIcon />} label="maintenance" sx={{ ml: 0.75, height: 20 }} />}
                    {hasCert(r) && (
                      <Tooltip title={`${r.force_ssl ? 'HTTPS (forced)' : 'HTTPS enabled'}${r.acme ? ' · renewed automatically' : ''}${r.cert_not_after > 0 ? ` · until ${new Date(r.cert_not_after * 1000).toLocaleDateString()}` : ''}`}>
                        <LockIcon sx={{ fontSize: 14, ml: 0.75, verticalAlign: 'middle', color: 'success.main' }} />
                      </Tooltip>
                    )}
                    {!hasCert(r) && r.covered_by && (
                      <Tooltip title={`HTTPS by the certificate ${r.covered_by}${r.force_ssl ? ' (forced)' : ''}`}>
                        <LockIcon sx={{ fontSize: 14, ml: 0.75, verticalAlign: 'middle', color: 'info.main' }} />
                      </Tooltip>
                    )}
                    {r.auth_usernames?.length > 0 && (
                      <Tooltip title={`Password protected: ${r.auth_usernames.join(', ')}`}>
                        <KeyIcon sx={{ fontSize: 14, ml: 0.75, verticalAlign: 'middle', color: 'text.secondary' }} />
                      </Tooltip>
                    )}
                  </TableCell>
                  <TableCell>
                    {r.mode === 'static' ? (
                      <Chip size="small" color="secondary" icon={<FolderIcon />} label={r.static_dir} />
                    ) : r.mode === 'redirect' ? (
                      <Chip size="small" color="info" icon={<CallMadeIcon />} label={`${r.redirect_code || 301} → ${r.redirect_url}`} />
                    ) : (
                      <Chip size="small" icon={<SwapHorizIcon />}
                        label={`${r.target_https ? 'https://' : ''}${r.target_ip}:${r.target_port}`} />
                    )}
                    {r.rate_limit > 0 && (
                      <Tooltip title={`Rate limit: ${r.rate_limit} req/s per IP; requests over it get 429`}>
                        <Chip size="small" variant="outlined" color="warning"
                          label={`${r.rate_limit} r/s`} sx={{ ml: 0.75 }} />
                      </Tooltip>
                    )}
                  </TableCell>
                  <TableCell align="right">
                    {!r.managed_by && !hasCert(r) && !r.covered_by && (
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
                    {!r.managed_by && (<>
                    <Tooltip title="Edit">
                      <IconButton onClick={() => setDialog({ mode: 'edit', route: withAuth(r) })}>
                        <EditIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete">
                      <IconButton color="error" onClick={() => remove(r)}>
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    </>)}
                  </TableCell>
                </TableRow>
                )))
              ])}
            </TableBody>
          </Table>
        </TableContainer>
      </Container>
      )}

      <Dialog open={!!dialog} onClose={() => setDialog(null)} fullWidth maxWidth="xs">
        <DialogTitle>
          {dialog?.mode === 'add'
            ? (dialog?.suffix ? `Add subdomain of ${dialog.suffix}` : 'Add domain')
            : 'Edit domain'}
        </DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            {dialog?.suffix ? (
              <TextField label="Subdomain" placeholder="abc" fullWidth autoFocus
                value={dialog?.route.domain
                  ? dialog.route.domain.slice(0, dialog.route.domain.length - dialog.suffix.length - 1)
                  : ''}
                onChange={(e) => {
                  const sub = e.target.value.trim().replace(/\.+$/, '').toLowerCase()
                  setDialog((d) => ({
                    ...d,
                    route: { ...d.route, domain: sub ? `${sub}.${d.suffix}` : '' }
                  }))
                }}
                InputProps={{
                  endAdornment: <InputAdornment position="end">.{dialog.suffix}</InputAdornment>
                }} />
            ) : (
              <TextField label="Domain" placeholder="example.com or *.example.com" fullWidth autoFocus
                value={dialog?.route.domain ?? ''} onChange={set('domain')} />
            )}
            <TextField label="Path prefix" placeholder="/" fullWidth
              helperText="Route only this path (e.g. /api) — the longest matching prefix wins"
              value={dialog?.route.path_prefix ?? '/'} onChange={set('path_prefix')} />
            <ToggleButtonGroup exclusive fullWidth color="primary" size="small"
              value={dialog?.route.mode ?? 'proxy'}
              onChange={(_, mode) => mode && setDialog((d) => ({ ...d, route: { ...d.route, mode } }))}>
              <ToggleButton value="proxy">Proxy</ToggleButton>
              <ToggleButton value="static">Static files</ToggleButton>
              <ToggleButton value="redirect">Redirect</ToggleButton>
            </ToggleButtonGroup>
            {dialog?.route.mode === 'redirect' ? (
              <>
                <TextField label="Redirect to" placeholder="https://example.com" fullWidth
                  helperText="The request path and query are appended unless the URL has its own path"
                  value={dialog?.route.redirect_url ?? ''} onChange={set('redirect_url')} />
                <FormControl fullWidth size="small">
                  <InputLabel>Status</InputLabel>
                  <Select label="Status" value={dialog?.route.redirect_code || 301} onChange={set('redirect_code')}>
                    <MenuItem value={301}>301 Moved permanently</MenuItem>
                    <MenuItem value={302}>302 Found (temporary)</MenuItem>
                    <MenuItem value={307}>307 Temporary, keeps the method</MenuItem>
                    <MenuItem value={308}>308 Permanent, keeps the method</MenuItem>
                  </Select>
                </FormControl>
              </>
            ) : (dialog?.route.mode ?? 'proxy') === 'proxy' ? (
              <>
                <TextField label="Target IP" placeholder="192.168.1.10" fullWidth
                  value={dialog?.route.target_ip ?? ''} onChange={set('target_ip')} />
                <TextField label="Target port" type="number" fullWidth
                  value={dialog?.route.target_port ?? 80} onChange={set('target_port')} />
                <FormControlLabel
                  control={<Switch checked={!!dialog?.route.target_https}
                    onChange={(e) => setDialog((d) => ({ ...d, route: { ...d.route, target_https: e.target.checked } }))} />}
                  label="Backend uses HTTPS" />
              </>
            ) : (
              <TextField label="Static directory" placeholder="/var/www/example.com" fullWidth
                helperText="Serves files from this folder (index.html for /)"
                value={dialog?.route.static_dir ?? ''} onChange={set('static_dir')} />
            )}
            {(dialog?.route.mode ?? 'proxy') === 'proxy' && (
              <>
                <Divider>
                  <Typography variant="caption" color="text.secondary">Health check</Typography>
                </Divider>
                <FormControlLabel
                  control={<Switch checked={!!dialog?.route.hc_enabled}
                    onChange={(e) => setDialog((d) => ({ ...d, route: { ...d.route, hc_enabled: e.target.checked } }))} />}
                  label="Monitor backend, push notification when down" />
                {dialog?.route.hc_enabled && (
                  <>
                    <Box sx={{ display: 'flex', gap: 2 }}>
                      <TextField label="Path" placeholder="/health" sx={{ flex: 2 }}
                        value={dialog?.route.hc_path ?? '/'} onChange={set('hc_path')} />
                      <TextField label="Interval (s)" type="number" sx={{ flex: 1 }}
                        value={dialog?.route.hc_interval ?? 30} onChange={set('hc_interval')} />
                    </Box>
                    <FormControl fullWidth size="small">
                      <InputLabel>Check type</InputLabel>
                      <Select label="Check type" value={dialog?.route.hc_type ?? 'status'}
                        onChange={(e) => setDialog((d) => ({ ...d, route: { ...d.route, hc_type: e.target.value } }))}>
                        <MenuItem value="status">HTTP status code</MenuItem>
                        <MenuItem value="contains">Body contains text</MenuItem>
                        <MenuItem value="json">JSON field equals value</MenuItem>
                      </Select>
                    </FormControl>
                    <TextField label="Expectation" fullWidth
                      helperText={hcExpectHelp[dialog?.route.hc_type ?? 'status']}
                      value={dialog?.route.hc_expect ?? ''} onChange={set('hc_expect')} />
                  </>
                )}
              </>
            )}
            <TextField label="Rate limit (req/s per IP)" type="number" fullWidth
              helperText="0 = unlimited. Requests over the limit get 429; persistent offenders are blocked (Settings). Browsers can burst 10+ req/s loading assets"
              value={dialog?.route.rate_limit ?? 0} onChange={set('rate_limit')} />
            <Divider>
              <Typography variant="caption" color="text.secondary">Options</Typography>
            </Divider>
            <FormControlLabel
              control={<Switch checked={!!dialog?.route.maintenance} onChange={setBool('maintenance')} />}
              label="Maintenance page (stop forwarding requests)" />
            {(dialog?.route.mode ?? 'proxy') === 'proxy' && (
              <>
                <FormControl fullWidth size="small">
                  <InputLabel>Backend protocol</InputLabel>
                  <Select label="Backend protocol" value={dialog?.route.backend_protocol || 'http1'} onChange={set('backend_protocol')}>
                    <MenuItem value="http1">HTTP/1.1 (WebSockets work)</MenuItem>
                    <MenuItem value="h2c" disabled={!!dialog?.route.target_https}>HTTP/2 cleartext (gRPC)</MenuItem>
                  </Select>
                </FormControl>
                <Box sx={{ display: 'flex', gap: 2 }}>
                  <TextField label="Timeout (s)" type="number" sx={{ flex: 1 }}
                    helperText="Until response headers; 0 = 60"
                    value={dialog?.route.timeout_seconds ?? 0} onChange={set('timeout_seconds')} />
                  <TextField label="Max body (MB)" type="number" sx={{ flex: 1 }}
                    helperText="0 = no limit"
                    value={dialog?.route.max_body_mb ?? 0} onChange={set('max_body_mb')} />
                </Box>
              </>
            )}
            <Typography variant="body2">Password protection (basic auth)</Typography>
            {(dialog?.route.auth || []).map((u, i) => (
              <Box key={i} sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                <TextField size="small" label="User" sx={{ flex: 1 }} value={u.user}
                  onChange={(e) => setAuth((a) => a.map((x, j) => j === i ? { ...x, user: e.target.value } : x))} />
                <TextField size="small" label="Password" type="password" sx={{ flex: 1 }} value={u.password}
                  placeholder={dialog?.route.auth_usernames?.includes(u.user) ? 'unchanged' : ''}
                  onChange={(e) => setAuth((a) => a.map((x, j) => j === i ? { ...x, password: e.target.value } : x))} />
                <IconButton size="small" onClick={() => setAuth((a) => a.filter((_, j) => j !== i))}>
                  <DeleteIcon fontSize="small" />
                </IconButton>
              </Box>
            ))}
            <Button size="small" startIcon={<AddIcon />} sx={{ alignSelf: 'flex-start' }}
              onClick={() => setAuth((a) => [...(a || []), { user: '', password: '' }])}>
              Add user
            </Button>
            {(dialog?.route.mode ?? 'proxy') !== 'redirect' && dialog?.route.webForm && (
              <>
                <Divider>
                  <Typography variant="caption" color="text.secondary">Redirects, access, headers (optional)</Typography>
                </Divider>
                <WebOptions form={dialog.route.webForm} onChange={setWeb} />
              </>
            )}
            <Divider>
              <Typography variant="caption" color="text.secondary">SSL (optional)</Typography>
            </Divider>
            {dialog?.route.covered_by && !hasCert(dialog.route) && (
              <Typography variant="caption" color="text.secondary">
                Served over HTTPS by the certificate {dialog.route.covered_by} (Certificates tab).
              </Typography>
            )}
            <FormControlLabel
              control={<Switch checked={!!dialog?.route.acme} onChange={setBool('acme')} />}
              label="Let's Encrypt certificate, renewed automatically" />
            {!dialog?.route.acme && (
            <Button variant="outlined" color="success" startIcon={<EnhancedEncryptionIcon />}
              disabled={!targetReady(dialog?.route)}
              onClick={() => save(true)}>
              Save & get Let's Encrypt certificate
            </Button>
            )}
            <Typography variant="caption" color="text.secondary" sx={{ textAlign: 'center' }}>
              — or set certificate paths manually —
            </Typography>
            <TextField label="Certificate file" placeholder="/etc/letsencrypt/live/example.com/fullchain.pem"
              fullWidth value={dialog?.route.cert_file ?? ''} onChange={set('cert_file')} />
            <TextField label="Private key file" placeholder="/etc/letsencrypt/live/example.com/privkey.pem"
              fullWidth value={dialog?.route.key_file ?? ''} onChange={set('key_file')} />
            <FormControlLabel
              control={<Switch checked={!!dialog?.route.force_ssl}
                disabled={!(dialog?.route.cert_file && dialog?.route.key_file) && !(dialog?.route.cert_not_after > 0) && !dialog?.route.covered_by}
                onChange={setBool('force_ssl')} />}
              label="Redirect HTTP → HTTPS" />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialog(null)}>Cancel</Button>
          <Button variant="contained" onClick={() => save()}
            disabled={!targetReady(dialog?.route)}>
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
