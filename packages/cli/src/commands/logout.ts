import { clearManagedSession, readManagedSession } from '../config'

export function logout() {
  const session = readManagedSession()
  if (!session) {
    console.log('Not logged in.')
    return
  }
  clearManagedSession()
  console.log(`Logged out from ${session.host}`)
}
