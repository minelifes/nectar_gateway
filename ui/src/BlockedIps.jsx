import { useCallback, useEffect, useState } from 'react'
import {
  Container, Paper, Table, TableBody, TableCell, TableContainer,
  TableHead, TableRow, IconButton, Tooltip, Chip, Typography, Box, Button
} from '@mui/material'
import {
  LockOpen as LockOpenIcon,
  Refresh as RefreshIcon,
  GppBad as GppBadIcon
} from '@mui/icons-material'

const fmt = (t) => new Date(t).toLocaleString()

const remaining = (t) => {
  const ms = new Date(t) - Date.now()
  if (ms <= 0) return 'expired'
  const h = Math.floor(ms / 3600000)
  const m = Math.floor((ms % 3600000) / 60000)
  return h > 0 ? `${h}h ${m}m` : `${m}m`
}

export default function BlockedIps({ onError }) {
  const [blocked, setBlocked] = useState([])

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/blocked')
      if (!res.ok) throw new Error(await res.text())
      setBlocked(await res.json())
    } catch (e) {
      onError('Failed to load blocked IPs: ' + e.message)
    }
  }, [onError])

  useEffect(() => { load() }, [load])

  const unblock = async (ip) => {
    const res = await fetch(`/api/blocked/${encodeURIComponent(ip)}`, { method: 'DELETE' })
    if (!res.ok) onError('Unblock failed')
    load()
  }

  return (
    <Container maxWidth="md" sx={{ mt: 4 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <GppBadIcon color="error" />
        <Typography variant="h6" sx={{ flexGrow: 1 }}>
          Blocked IPs {blocked.length > 0 && `(${blocked.length})`}
        </Typography>
        <Button size="small" startIcon={<RefreshIcon />} onClick={load}>Refresh</Button>
      </Box>
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>IP address</TableCell>
              <TableCell>Reason</TableCell>
              <TableCell>Blocked at</TableCell>
              <TableCell>Expires in</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {blocked.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} align="center" sx={{ py: 6, color: 'text.secondary' }}>
                  No blocked IPs. Scanners are blocked automatically for 24 hours.
                </TableCell>
              </TableRow>
            )}
            {blocked.map((b) => (
              <TableRow key={b.ip} hover>
                <TableCell sx={{ fontFamily: 'monospace' }}>{b.ip}</TableCell>
                <TableCell sx={{ wordBreak: 'break-all' }}>{b.reason}</TableCell>
                <TableCell>{fmt(b.blocked_at)}</TableCell>
                <TableCell>
                  <Chip size="small" variant="outlined" color="warning" label={remaining(b.expires_at)} />
                </TableCell>
                <TableCell align="right">
                  <Tooltip title="Unblock">
                    <IconButton color="primary" onClick={() => unblock(b.ip)}>
                      <LockOpenIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Container>
  )
}
