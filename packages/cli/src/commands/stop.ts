import { existsSync, readFileSync, unlinkSync } from 'node:fs'
import { getPidFile } from '../config'

export async function stop() {
  const pidFile = getPidFile()
  if (!existsSync(pidFile)) {
    console.log('agent.pw is not running.')
    return
  }

  const pid = parseInt(readFileSync(pidFile, 'utf-8').trim(), 10)
  try {
    process.kill(pid, 'SIGTERM')
    console.log(`Stopped agent.pw (PID ${pid}).`)
  } catch {
    console.log('agent.pw process not found. Cleaning up PID file.')
  }
  try { unlinkSync(pidFile) } catch { /* ignore */ }
}
