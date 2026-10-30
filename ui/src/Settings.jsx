import { useEffect, useState } from 'react'
import {
  Container, Paper, Stack, TextField, Button, Typography, Divider, FormControl, InputLabel, Select, MenuItem
} from '@mui/material'

// Settings edits the runtime settings (GET/PUT /api/settings). The DNS token is write-only: an empty field
// keeps the stored token.
export default function Settings({ onError, onOk, onChange }) {
  const [v, setV] = useState(null)
  const [token, setToken] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    fetch('/api/settings')
      .then(async (res) => {
        if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.statusText)
        return res.json()
      })
      .then(setV)
      .catch((e) => onError('Failed to load settings: ' + e.message))
  }, [onError])

  if (!v) return null
  const set = (field) => (e) => setV((s) => ({ ...s, [field]: e.target.value }))

  const save = async () => {
    setSaving(true)
    const body = {
      acme_email: v.acme_email.trim(),
      fallback_http: v.fallback_http.trim(),
      fallback_tls: v.fallback_tls.trim(),
      dns_provider: v.dns_provider,
      rate_limit_block_minutes: Number(v.rate_limit_block_minutes) || 0
    }
    if (token.trim()) body.dns_api_token = token.trim()
    if (!v.dns_provider) body.dns_api_token = ''
    try {
      const res = await fetch('/api/settings', {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
      })
      const out = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(out.error || res.statusText)
      setV(out)
      setToken('')
      onChange?.(out)
      onOk('Settings saved')
    } catch (e) {
      onError('Save failed: ' + e.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Container maxWidth="sm" sx={{ mt: 4, mb: 4 }}>
      <Paper sx={{ p: 3 }}>
        <Stack spacing={2}>
          <Typography variant="subtitle1">Let&apos;s Encrypt</Typography>
          <TextField label="Account email" fullWidth value={v.acme_email ?? ''} onChange={set('acme_email')}
            helperText="Expiry warnings from Let's Encrypt go here (optional)" />

          <Divider />
          <Typography variant="subtitle1">DNS (wildcard certificates)</Typography>
          <FormControl fullWidth size="small">
            <InputLabel>DNS provider</InputLabel>
            <Select label="DNS provider" value={v.dns_provider ?? ''} onChange={set('dns_provider')}>
              <MenuItem value="">None</MenuItem>
              <MenuItem value="cloudflare">Cloudflare</MenuItem>
            </Select>
          </FormControl>
          {v.dns_provider && (
            <TextField label="API token" type="password" fullWidth value={token}
              onChange={(e) => setToken(e.target.value)}
              helperText={`${v.dns_token_set ? 'A token is stored — leave empty to keep it. ' : ''}Cloudflare: a token with Zone → Zone → Read and Zone → DNS → Edit for your zones`} />
          )}

          <Divider />
          <Typography variant="subtitle1">Rate limits</Typography>
          <TextField label="Block persistent offenders, minutes" type="number" fullWidth
            value={v.rate_limit_block_minutes ?? 10} onChange={set('rate_limit_block_minutes')}
            helperText="Requests over a domain's limit get 429. A client refused more than 10× the limit within a minute is blocked this long; 0 = never block" />

          <Divider />
          <Typography variant="subtitle1">Unknown hosts</Typography>
          <TextField label="HTTP fallback (host:port)" fullWidth value={v.fallback_http ?? ''} onChange={set('fallback_http')}
            helperText="Plain HTTP for hosts without a route goes here (e.g. the old ingress during a migration); empty = 410 Gone" />
          <TextField label="TLS passthrough (host:port)" fullWidth value={v.fallback_tls ?? ''} onChange={set('fallback_tls')}
            helperText="HTTPS for hosts without a certificate here is passed through unchanged; empty = refuse" />

          <Button variant="contained" disabled={saving || (v.dns_provider && !v.dns_token_set && !token.trim())} onClick={save}>
            {saving ? 'Saving…' : 'Save'}
          </Button>
        </Stack>
      </Paper>
    </Container>
  )
}
