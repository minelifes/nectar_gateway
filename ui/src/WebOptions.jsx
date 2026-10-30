import {
  Box, Button, Checkbox, FormControl, FormControlLabel, IconButton, InputLabel, MenuItem, Select, Stack, Switch,
  TextField, Typography
} from '@mui/material'
import { Add as AddIcon, Delete as DeleteIcon } from '@mui/icons-material'

// The route's "web" options are edited as a flat form and converted back on save.

const headersToText = (h) => Object.entries(h || {}).map(([k, v]) => `${k}: ${v}`).join('\n')
const textToHeaders = (t) => {
  const out = {}
  for (const line of (t || '').split('\n')) {
    const i = line.indexOf(':')
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim()
  }
  return out
}
const lines = (t) => (t || '').split(/[\n,]/).map((s) => s.trim()).filter(Boolean)

export const webToForm = (w) => ({
  redirects: (w?.redirects || []).map((r) => ({ from: r.from, to: r.to, code: r.code || 301, prefix: !!r.prefix })),
  allowIPs: (w?.allow_ips || []).join('\n'),
  responseHeaders: headersToText(w?.response_headers),
  requestHeaders: headersToText(w?.request_headers),
  corsOn: !!w?.cors,
  corsOrigins: (w?.cors?.origins || []).join('\n'),
  corsCredentials: !!w?.cors?.credentials,
  compress: !!w?.compress,
  hsts: w?.hsts || 0,
  hstsSubdomains: !!w?.hsts_subdomains
})

export const formToWeb = (f) => {
  const w = {}
  const redirects = f.redirects.filter((r) => r.from.trim() && r.to.trim())
    .map((r) => ({ from: r.from.trim(), to: r.to.trim(), code: Number(r.code) || 301, prefix: r.prefix }))
  if (redirects.length) w.redirects = redirects
  const allow = lines(f.allowIPs)
  if (allow.length) w.allow_ips = allow
  const rh = textToHeaders(f.responseHeaders)
  if (Object.keys(rh).length) w.response_headers = rh
  const qh = textToHeaders(f.requestHeaders)
  if (Object.keys(qh).length) w.request_headers = qh
  if (f.corsOn && lines(f.corsOrigins).length) w.cors = { origins: lines(f.corsOrigins), credentials: f.corsCredentials }
  if (f.compress) w.compress = true
  if (Number(f.hsts) > 0) {
    w.hsts = Number(f.hsts)
    if (f.hstsSubdomains) w.hsts_subdomains = true
  }
  return w // {} clears every option
}

export default function WebOptions({ form, onChange }) {
  const set = (field) => (e) => onChange({ ...form, [field]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })
  const setRule = (i, patch) => onChange({ ...form, redirects: form.redirects.map((r, j) => (j === i ? { ...r, ...patch } : r)) })
  return (
    <Stack spacing={2}>
      <Typography variant="body2">Redirect rules</Typography>
      {form.redirects.map((r, i) => (
        <Box key={i} sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
          <TextField size="small" label="From path" placeholder="/old" sx={{ flex: '1 1 90px' }} value={r.from}
            onChange={(e) => setRule(i, { from: e.target.value })} />
          <TextField size="small" label="To" placeholder="/new or https://…" sx={{ flex: '2 1 140px' }} value={r.to}
            onChange={(e) => setRule(i, { to: e.target.value })} />
          <Select size="small" value={r.code} onChange={(e) => setRule(i, { code: e.target.value })}>
            {[301, 302, 307, 308].map((c) => <MenuItem key={c} value={c}>{c}</MenuItem>)}
          </Select>
          <Tooltipless label="+ subpaths">
            <Checkbox size="small" checked={r.prefix} onChange={(e) => setRule(i, { prefix: e.target.checked })} />
          </Tooltipless>
          <IconButton size="small" onClick={() => onChange({ ...form, redirects: form.redirects.filter((_, j) => j !== i) })}>
            <DeleteIcon fontSize="small" />
          </IconButton>
        </Box>
      ))}
      <Button size="small" startIcon={<AddIcon />} sx={{ alignSelf: 'flex-start' }}
        onClick={() => onChange({ ...form, redirects: [...form.redirects, { from: '', to: '', code: 301, prefix: false }] })}>
        Add rule
      </Button>
      <TextField label="Allowed IPs" multiline minRows={2} fullWidth value={form.allowIPs} onChange={set('allowIPs')}
        placeholder={'203.0.113.0/24\n2001:db8::/32'}
        helperText="One IP or CIDR per line; others get 403. Empty = everyone" />
      <TextField label="Response headers" multiline minRows={2} fullWidth value={form.responseHeaders} onChange={set('responseHeaders')}
        placeholder={'X-Frame-Options: DENY\nServer:'} helperText="Name: value per line; an empty value removes the header" />
      <TextField label="Request headers (to the backend)" multiline minRows={1} fullWidth value={form.requestHeaders}
        onChange={set('requestHeaders')} placeholder="X-Env: staging" />
      <FormControlLabel control={<Switch checked={form.corsOn} onChange={set('corsOn')} />} label="CORS" />
      {form.corsOn && (
        <>
          <TextField label="Allowed origins" multiline minRows={1} fullWidth value={form.corsOrigins} onChange={set('corsOrigins')}
            placeholder="https://app.example.com" helperText={'One per line, or * for any site (then without credentials)'} />
          <FormControlLabel control={<Switch checked={form.corsCredentials} onChange={set('corsCredentials')} />}
            label="Allow cookies / credentials" />
        </>
      )}
      <FormControlLabel control={<Switch checked={form.compress} onChange={set('compress')} />}
        label="Compress text responses (gzip)" />
      <FormControl fullWidth size="small">
        <InputLabel>HSTS</InputLabel>
        <Select label="HSTS" value={form.hsts} onChange={set('hsts')}>
          <MenuItem value={0}>Off</MenuItem>
          <MenuItem value={300}>5 minutes (testing)</MenuItem>
          <MenuItem value={86400}>1 day</MenuItem>
          <MenuItem value={15768000}>6 months</MenuItem>
          <MenuItem value={31536000}>1 year</MenuItem>
          <MenuItem value={63072000}>2 years</MenuItem>
        </Select>
      </FormControl>
      {Number(form.hsts) > 0 && (
        <FormControlLabel control={<Switch checked={form.hstsSubdomains} onChange={set('hstsSubdomains')} />}
          label="Include subdomains" />
      )}
    </Stack>
  )
}

function Tooltipless({ label, children }) {
  return <FormControlLabel sx={{ mr: 0 }} control={children} label={<Typography variant="caption">{label}</Typography>} />
}
