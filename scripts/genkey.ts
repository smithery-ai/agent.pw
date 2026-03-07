import { generateKeyPairHex } from '../packages/server/src/biscuit'

const { privateKey, publicKey } = generateKeyPairHex()
console.log(`BISCUIT_PRIVATE_KEY=${privateKey}`)
console.log(`BISCUIT_PUBLIC_KEY=${publicKey}`)
