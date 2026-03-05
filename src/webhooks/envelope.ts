/**
 * Ed25519 JWKS endpoint support.
 *
 * Publishes the Ed25519 public key at /.well-known/jwks.json so clients
 * can verify webhook envelope signatures.
 */

function hexToBytes(hex: string) {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
  }
  return bytes
}

function base64urlEncode(bytes: Uint8Array) {
  const base64 = btoa(String.fromCharCode(...bytes))
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Build a JWK representation of the Ed25519 public key.
 */
export function buildJwks(publicKeyHex: string) {
  // Strip the ed25519/ prefix if present
  const rawHex = publicKeyHex.replace(/^ed25519\//, '')
  const publicKeyBytes = hexToBytes(rawHex)

  return {
    keys: [
      {
        kty: 'OKP' as const,
        crv: 'Ed25519' as const,
        x: base64urlEncode(publicKeyBytes),
        use: 'sig' as const,
        kid: 'agentpw-ed25519-1',
      },
    ],
  }
}
