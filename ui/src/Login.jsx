import { useState } from 'react'
import {
  Box, Paper, Typography, TextField, Button, Alert, Stack
} from '@mui/material'

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.error || 'login failed')
      }
      onLogin()
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <Box sx={{
      minHeight: '100vh', display: 'flex',
      alignItems: 'center', justifyContent: 'center'
    }}>
      <Paper elevation={6} sx={{ p: 4, width: 360 }}>
        <Stack alignItems="center" spacing={1} sx={{ mb: 3 }}>
          <Box component="img" src="/icon-192.png" alt="Nectar" sx={{ width: 72, height: 72, borderRadius: '18px' }} />
          <Typography variant="h5">Nectar Gateway</Typography>
          <Typography variant="body2" color="text.secondary">
            Sign in to manage your domains
          </Typography>
        </Stack>
        <form onSubmit={submit}>
          <Stack spacing={2}>
            {error && <Alert severity="error">{error}</Alert>}
            <TextField label="Username" fullWidth autoFocus autoComplete="username"
              value={username} onChange={(e) => setUsername(e.target.value)} />
            <TextField label="Password" type="password" fullWidth autoComplete="current-password"
              value={password} onChange={(e) => setPassword(e.target.value)} />
            <Button type="submit" variant="contained" size="large" fullWidth
              disabled={loading || !username || !password}>
              {loading ? 'Signing in…' : 'Sign in'}
            </Button>
          </Stack>
        </form>
      </Paper>
    </Box>
  )
}
