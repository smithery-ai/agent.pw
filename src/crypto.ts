const ALGO = 'AES-GCM'
const KEY_LENGTH = 256

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

async function importKey(hexKey: string): Promise<CryptoKey> {
  const keyBytes = hexToBytes(hexKey)
  return crypto.subtle.importKey('raw', keyBytes, { name: ALGO, length: KEY_LENGTH }, false, [
    'encrypt',
    'decrypt',
  ])
}

export async function encrypt(plaintext: string, hexKey: string): Promise<{ encrypted: string; iv: string }> {
  const key = await importKey(hexKey)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const encoded = new TextEncoder().encode(plaintext)
  const ciphertext = await crypto.subtle.encrypt({ name: ALGO, iv }, key, encoded)
  return {
    encrypted: bytesToBase64(new Uint8Array(ciphertext)),
    iv: bytesToBase64(iv),
  }
}

export async function decrypt(encrypted: string, iv: string, hexKey: string): Promise<string> {
  const key = await importKey(hexKey)
  const ciphertext = base64ToBytes(encrypted)
  const ivBytes = base64ToBytes(iv)
  const plaintext = await crypto.subtle.decrypt({ name: ALGO, iv: ivBytes }, key, ciphertext)
  return new TextDecoder().decode(plaintext)
}

export { hexToBytes, bytesToHex }
