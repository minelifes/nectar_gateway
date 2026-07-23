import { useState } from 'react'
import {
  Dialog, DialogTitle, DialogContent, DialogActions, Button, TextField,
  Stack, Alert, List, ListItem, ListItemText, Chip, Typography, Divider
} from '@mui/material'
import { UploadFile as UploadFileIcon, Lock as LockIcon } from '@mui/icons-material'
import { Box, Tooltip } from '@mui/material'

export default function ImportNginx({ open, onClose, onImported }) {
  const [config, setConfig] = useState('')
  const [preview, setPreview] = useState(null) // {routes, skipped}
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const close = () => {
    setConfig(''); setPreview(null); setError('')
    onClose()
  }

  const call = async (dryRun) => {
    setBusy(true); setError('')
    try {
      const res = await fetch('/api/import/nginx', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config, dry_run: dryRun })
      })
      const body = await res.json()
      if (!res.ok) throw new Error(body.error || res.statusText)
      if (dryRun) {
        setPreview(body)
      } else {
        onImported(body)
        close()
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  const onFile = (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    file.text().then((t) => { setConfig(t); setPreview(null) })
    e.target.value = ''
  }

  return (
    <Dialog open={open} onClose={close} fullWidth maxWidth="sm">
      <DialogTitle>Import from nginx</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <TextField
            label="nginx configuration"
            placeholder={'Paste nginx.conf / sites-enabled content here…\n\nserver {\n  server_name example.com;\n  location / { proxy_pass http://127.0.0.1:3000; }\n}'}
            multiline minRows={8} maxRows={16} fullWidth
            value={config}
            onChange={(e) => { setConfig(e.target.value); setPreview(null) }}
          />
          <Button component="label" startIcon={<UploadFileIcon />} size="small" sx={{ alignSelf: 'flex-start' }}>
            Load from file
            <input type="file" hidden onChange={onFile} />
          </Button>

          {preview && (
            <>
              <Divider />
              <Typography variant="subtitle2">
                {preview.routes.length} route(s) found
              </Typography>
              <List dense disablePadding>
                {preview.routes.map((r, i) => (
                  <ListItem key={i} disableGutters>
                    <ListItemText
                      primary={
                        <Box component="span" sx={{ display: 'inline-flex', alignItems: 'center', gap: 0.75, flexWrap: 'wrap' }}>
                          {r.domain}
                          {r.mode === 'static'
                            ? <Chip size="small" color="secondary" label={r.static_dir} />
                            : <Chip size="small" label={`${r.target_ip}:${r.target_port}`} />}
                          {r.cert_file && (
                            <Tooltip title={r.force_ssl ? 'HTTPS, HTTP redirects to HTTPS' : 'HTTPS enabled'}>
                              <LockIcon sx={{ fontSize: 14, color: 'success.main' }} />
                            </Tooltip>
                          )}
                          {r.force_ssl && <Chip size="small" variant="outlined" color="success" label="force https" sx={{ height: 18 }} />}
                        </Box>
                      }
                      secondary={<>
                        {r.mode && r.cert_file ? (
                            <ul>
                              <li>cert: {r.cert_file}</li>
                              {r.key_file && <li>key: {r.key_file}</li>}
                            </ul>
                        ) : (
                            ' · no ssl'
                        )}
                      </>}
                      secondaryTypographyProps={{ sx: { wordBreak: 'break-all' } }} />
                  </ListItem>
                ))}
              </List>
              {preview.skipped.length > 0 && (
                <Alert severity="warning">
                  Skipped: {preview.skipped.join('; ')}
                </Alert>
              )}
            </>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={close}>Cancel</Button>
        {!preview ? (
          <Button variant="contained" disabled={!config.trim() || busy} onClick={() => call(true)}>
            Parse
          </Button>
        ) : (
          <Button variant="contained" disabled={busy || preview.routes.length === 0} onClick={() => call(false)}>
            Import {preview.routes.length} route(s)
          </Button>
        )}
      </DialogActions>
    </Dialog>
  )
}
