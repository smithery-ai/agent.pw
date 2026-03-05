export function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message
  if (typeof e === 'string') return e
  try {
    return JSON.stringify(e)
  } catch /* v8 ignore start */ {
    return String(e)
  } /* v8 ignore stop */
}

export function randomId() {
  const bytes = new Uint8Array(24)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

export function deriveDisplayName(hostname: string) {
  // api.linear.app → Linear, api.github.com → Github
  const parts = hostname.replace(/^(api|www)\./, '').split('.')
  const name = parts[0]
  return name.charAt(0).toUpperCase() + name.slice(1)
}

export const RESERVED_PATHS = new Set(['auth', 'tokens', 'services', 'vaults', 'keys', 'proxy', 'hooks', '.well-known', 'favicon.ico'])

const FILE_EXTENSIONS = new Set([
  // Web / server
  'json', 'html', 'htm', 'xml', 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml',
  'asp', 'aspx', 'axd', 'jsp', 'jspx', 'cgi', 'action', 'do', 'cfm',
  // Config / env
  'env', 'txt', 'yaml', 'yml', 'toml', 'config', 'conf', 'cfg', 'ini', 'properties',
  'log', 'bak', 'old', 'orig', 'save', 'swp', 'swo', 'tmp', 'temp',
  // Data
  'sql', 'db', 'sqlite', 'csv', 'tsv', 'xls', 'xlsx', 'doc', 'docx', 'pdf',
  // Code / scripts
  'js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx', 'css', 'scss', 'less', 'map',
  'py', 'pyc', 'pyo', 'rb', 'pl', 'pm', 'sh', 'bash', 'zsh', 'bat', 'cmd', 'ps1',
  'c', 'h', 'cpp', 'java', 'class', 'jar', 'go', 'rs', 'lua', 'r', 'swift',
  'src', 'inc', 'bak',
  // Certificates / keys / secrets
  'key', 'pem', 'crt', 'cer', 'csr', 'p12', 'pfx', 'jks', 'der',
  // Archives
  'zip', 'tar', 'gz', 'tgz', 'bz2', 'xz', 'rar', '7z',
  // Assets / fonts
  'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'webp', 'bmp', 'tiff',
  'woff', 'woff2', 'ttf', 'eot', 'otf',
  'mp3', 'mp4', 'avi', 'mov', 'wav', 'flac',
  // System
  'pwd', 'grp', 'shadow', 'passwd', 'htaccess', 'htpasswd', 'lock', 'pid',
  // Misc
  'md', 'rst', 'tex', 'rtf', 'wsdl', 'dtd', 'xsd', 'xsl',
])

export function relativeTime(date: Date) {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000)
  if (seconds < 60) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days === 1) return '1 day ago'
  if (days < 30) return `${days} days ago`
  const months = Math.floor(days / 30)
  if (months === 1) return '1 month ago'
  return `${months} months ago`
}

/** Filter out auto-registered junk (file paths, bare words) — only keep real hostnames. */
export function looksLikeHostname(service: string) {
  if (!service.includes('.')) return false
  if (service.startsWith('.')) return false
  const ext = service.split('.').pop()!.toLowerCase()
  if (FILE_EXTENSIONS.has(ext)) return false
  // TLDs are all-alpha; extensions with digits (e.g. php5, log4) are not real TLDs
  if (/\d/.test(ext)) return false
  return true
}
