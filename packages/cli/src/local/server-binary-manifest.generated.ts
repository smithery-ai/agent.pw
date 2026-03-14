import pkg from '../../package.json'

export interface ServerBinaryAsset {
  fileName: string
  url: string
  sha256: string
}

const versionTag = `agent.pw-v${pkg.version}`
const baseUrl = `https://github.com/smithery-ai/agent.pw/releases/download/${versionTag}`

export const SERVER_BINARY_MANIFEST: Record<string, ServerBinaryAsset> = {
  'darwin-arm64': {
    fileName: 'agentpw-local-server-darwin-arm64',
    url: `${baseUrl}/agentpw-local-server-darwin-arm64`,
    sha256: '__GENERATED_AT_RELEASE__',
  },
  'darwin-x64': {
    fileName: 'agentpw-local-server-darwin-x64',
    url: `${baseUrl}/agentpw-local-server-darwin-x64`,
    sha256: '__GENERATED_AT_RELEASE__',
  },
  'linux-arm64': {
    fileName: 'agentpw-local-server-linux-arm64',
    url: `${baseUrl}/agentpw-local-server-linux-arm64`,
    sha256: '__GENERATED_AT_RELEASE__',
  },
  'linux-x64': {
    fileName: 'agentpw-local-server-linux-x64',
    url: `${baseUrl}/agentpw-local-server-linux-x64`,
    sha256: '__GENERATED_AT_RELEASE__',
  },
  'win32-x64': {
    fileName: 'agentpw-local-server-windows-x64.exe',
    url: `${baseUrl}/agentpw-local-server-windows-x64.exe`,
    sha256: '__GENERATED_AT_RELEASE__',
  },
}
