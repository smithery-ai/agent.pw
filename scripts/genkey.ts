import { KeyPair, SignatureAlgorithm } from '@biscuit-auth/biscuit-wasm'

const kp = new KeyPair(SignatureAlgorithm.Ed25519)
console.log(`BISCUIT_PRIVATE_KEY=${kp.getPrivateKey().toString()}`)
console.log(`BISCUIT_PUBLIC_KEY=${kp.getPublicKey().toString()}`)
