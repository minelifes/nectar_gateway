import { useCallback, useEffect, useState } from 'react'
import {
  Container, Paper, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, IconButton, Button,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField, Stack, Chip, Tooltip, FormControlLabel,
  Switch, ToggleButton, ToggleButtonGroup, Typography, Box, Alert
} from '@mui/material'
import {
  Add as AddIcon, Refresh as RefreshIcon, Delete as DeleteIcon, UploadFile as UploadFileIcon
} from '@mui/icons-material'

const statusColor = { valid: 'success', expiring: 'warning', expired: 'error', failed: 'error', pending: 'default' }

const fmtDate = (unix) => unix > 0 ? new Date(unix * 1000).toLocaleDateString() : '—'

// Certificates are standalone certificates (wildcards such as *.example.com, or a host shared by several
// routes). Hosts without a certificate of their own are served by a matching one.
export default function Certificates({ onError, onOk, dnsReady }) {
  const [certs, setCerts] = useState([])
  const [dialog, setDialog] = useState(null) // null | {domain, include_apex, kind:'acme'|'upload', cert_pem, key_pem}
  const [upload, setUpload] = useState(null) // null | {cert, cert_pem, key_pem}
  const [busy, setBusy] = useState(null)

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/certificates')
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.statusText)
      setCerts(await res.json())
    } catch (e) {
      onError('Failed to load certificates: ' + e.message)
    }
  }, [onError])

  useEffect(() => { load() }, [load])
  // poll while an order is pending
  useEffect(() => {
    if (!certs.some((c) => c.status === 'pending' && c.acme)) return
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [certs, load])

  const call = async (what, url, init) => {
    try {
      const res = await fetch(url, init)
      const body = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(body.error || res.statusText)
      return body
    } catch (e) {
      onError(`${what} failed: ${e.message}`)
      return null
    } finally {
      load()
    }
  }

  const create = async () => {
    const d = dialog
    const body = { domain: d.domain.trim().toLowerCase(), include_apex: d.include_apex }
    if (d.kind === 'upload') Object.assign(body, { acme: false, cert_pem: d.cert_pem, key_pem: d.key_pem })
    setBusy('create')
    const ok = await call('Create', '/api/certificates', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    })
    setBusy(null)
    if (ok) {
      setDialog(null)
      onOk(d.kind === 'acme' ? `Ordering ${body.domain} — this takes a minute` : `Certificate for ${body.domain} saved`)
    }
  }

  const renew = async (c) => {
    setBusy(c.id)
    if (await call('Renew', `/api/certificates/${c.id}/renew`, { method: 'POST' })) onOk(`Renewal of ${c.domain} started`)
    setBusy(null)
  }

  const remove = async (c) => {
    const users = c.serves?.length ? `\n\nIt serves ${c.serves.join(', ')} — they lose HTTPS.` : ''
    if (!confirm(`Delete the certificate ${c.domain}?${users}`)) return
    await call('Delete', `/api/certificates/${c.id}`, { method: 'DELETE' })
  }

  const savePair = async () => {
    const ok = await call('Upload', `/api/certificates/${upload.cert.id}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cert_pem: upload.cert_pem, key_pem: upload.key_pem })
    })
    if (ok) {
      setUpload(null)
      onOk(`Certificate for ${upload.cert.domain} replaced`)
    }
  }

  const readFile = (field, setter) => async (e) => {
    const f = e.target.files?.[0]
    if (f) {
      const text = await f.text()
      setter((d) => ({ ...d, [field]: text }))
    }
  }

  const wildcard = dialog?.domain?.trim().startsWith('*.')
  const valid = dialog && /^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(dialog.domain.trim()) &&
    (dialog.kind === 'acme' || (dialog.cert_pem && dialog.key_pem))

  return (
    <Container maxWidth="md" sx={{ mt: 4 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
        <Typography variant="body2" color="text.secondary" sx={{ flexGrow: 1 }}>
          Wildcard and shared certificates. A domain without a certificate of its own uses a matching one here.
        </Typography>
        <Button variant="contained" startIcon={<AddIcon />}
          onClick={() => setDialog({ domain: '', include_apex: true, kind: 'acme', cert_pem: '', key_pem: '' })}>
          Add certificate
        </Button>
      </Box>
      {!dnsReady && (
        <Alert severity="info" sx={{ mb: 2 }}>
          Let&apos;s Encrypt wildcard certificates need a DNS provider (Settings → DNS). Uploaded certificates work without one.
        </Alert>
      )}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Certificate</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Serves</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {certs.length === 0 && (
              <TableRow>
                <TableCell colSpan={4} align="center" sx={{ py: 6, color: 'text.secondary' }}>
                  No certificates. Domains get their own Let&apos;s Encrypt certificate from the Domains tab.
                </TableCell>
              </TableRow>
            )}
            {certs.map((c) => (
              <TableRow key={c.id} hover>
                <TableCell>
                  <Typography variant="body2">{c.domain}</Typography>
                  <Typography variant="caption" color="text.secondary">
                    {(c.names || []).join(', ')} · {c.acme ? "Let's Encrypt" : 'uploaded'}
                  </Typography>
                  {c.managed_by && (
                    <Tooltip title={`Managed by ${c.managed_by} — change it there`}>
                      <Chip size="small" variant="outlined" label={c.managed_by} sx={{ ml: 0.75, height: 20 }} />
                    </Tooltip>
                  )}
                </TableCell>
                <TableCell>
                  <Tooltip title={c.last_error || ''}>
                    <Chip size="small" color={statusColor[c.status] || 'default'} label={c.status} />
                  </Tooltip>
                  <Typography variant="caption" color="text.secondary" display="block">
                    {c.not_after > 0 ? `until ${fmtDate(c.not_after)}` : c.last_error ? '' : 'ordering…'}
                  </Typography>
                  {c.last_error && (
                    <Typography variant="caption" color="error" display="block"
                      sx={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {c.last_error}
                    </Typography>
                  )}
                </TableCell>
                <TableCell>
                  <Typography variant="caption">{c.serves?.length ? c.serves.join(', ') : '—'}</Typography>
                </TableCell>
                <TableCell align="right">
                  {!c.managed_by && (<>
                    {c.acme ? (
                      <Tooltip title="Renew now">
                        <span>
                          <IconButton disabled={busy === c.id} onClick={() => renew(c)}><RefreshIcon fontSize="small" /></IconButton>
                        </span>
                      </Tooltip>
                    ) : (
                      <Tooltip title="Replace the certificate files">
                        <IconButton onClick={() => setUpload({ cert: c, cert_pem: '', key_pem: '' })}>
                          <UploadFileIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    )}
                    <Tooltip title="Delete">
                      <IconButton color="error" onClick={() => remove(c)}><DeleteIcon fontSize="small" /></IconButton>
                    </Tooltip>
                  </>)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={!!dialog} onClose={() => setDialog(null)} fullWidth maxWidth="xs">
        <DialogTitle>Add certificate</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="Domain" placeholder="*.example.com" fullWidth autoFocus
              helperText="A wildcard covers one level: *.example.com serves api.example.com, not a.b.example.com"
              value={dialog?.domain ?? ''} onChange={(e) => setDialog((d) => ({ ...d, domain: e.target.value }))} />
            {wildcard && (
              <FormControlLabel
                control={<Switch checked={!!dialog?.include_apex}
                  onChange={(e) => setDialog((d) => ({ ...d, include_apex: e.target.checked }))} />}
                label={`Also cover ${dialog.domain.trim().slice(2) || 'the apex'}`} />
            )}
            <ToggleButtonGroup exclusive fullWidth size="small" color="primary" value={dialog?.kind ?? 'acme'}
              onChange={(_, kind) => kind && setDialog((d) => ({ ...d, kind }))}>
              <ToggleButton value="acme">Let&apos;s Encrypt</ToggleButton>
              <ToggleButton value="upload">Upload files</ToggleButton>
            </ToggleButtonGroup>
            {dialog?.kind === 'acme' && wildcard && !dnsReady && (
              <Alert severity="warning">Set up a DNS provider in Settings first: wildcards are validated over DNS.</Alert>
            )}
            {dialog?.kind === 'upload' && (<>
              <Button variant="outlined" component="label" startIcon={<UploadFileIcon />}>
                {dialog.cert_pem ? 'Certificate chain loaded' : 'Certificate chain (fullchain.pem)'}
                <input hidden type="file" accept=".pem,.crt,.cer" onChange={readFile('cert_pem', setDialog)} />
              </Button>
              <Button variant="outlined" component="label" startIcon={<UploadFileIcon />}>
                {dialog.key_pem ? 'Private key loaded' : 'Private key (privkey.pem)'}
                <input hidden type="file" accept=".pem,.key" onChange={readFile('key_pem', setDialog)} />
              </Button>
            </>)}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialog(null)}>Cancel</Button>
          <Button variant="contained" disabled={!valid || busy === 'create'} onClick={create}>
            {dialog?.kind === 'upload' ? 'Save' : 'Order'}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={!!upload} onClose={() => setUpload(null)} fullWidth maxWidth="xs">
        <DialogTitle>Replace {upload?.cert.domain}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Button variant="outlined" component="label" startIcon={<UploadFileIcon />}>
              {upload?.cert_pem ? 'Certificate chain loaded' : 'Certificate chain (fullchain.pem)'}
              <input hidden type="file" accept=".pem,.crt,.cer" onChange={readFile('cert_pem', setUpload)} />
            </Button>
            <Button variant="outlined" component="label" startIcon={<UploadFileIcon />}>
              {upload?.key_pem ? 'Private key loaded' : 'Private key (privkey.pem)'}
              <input hidden type="file" accept=".pem,.key" onChange={readFile('key_pem', setUpload)} />
            </Button>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setUpload(null)}>Cancel</Button>
          <Button variant="contained" disabled={!upload?.cert_pem || !upload?.key_pem} onClick={savePair}>Save</Button>
        </DialogActions>
      </Dialog>
    </Container>
  )
}
