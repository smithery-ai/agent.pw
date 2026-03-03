import { generateKeyPairHex } from '../src/biscuit'

const { privateKey, publicKey } = generateKeyPairHex()
console.log(`BISCUIT_PRIVATE_KEY=${privateKey}`)
console.log(`BISCUIT_PUBLIC_KEY=${publicKey}`)

const encKeyBytes = new Uint8Array(32)
crypto.getRandomValues(encKeyBytes)
const encKey = Buffer.from(encKeyBytes).toString('base64')
console.log(`ENCRYPTION_KEY=${encKey}`)
