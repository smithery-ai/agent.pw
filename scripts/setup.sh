#!/usr/bin/env bash
set -euo pipefail

# Auth Proxy — Local Setup
# Generates secrets, creates .dev.vars, and applies D1 migrations locally.

cd "$(dirname "$0")/.."

echo "=== Auth Proxy Setup ==="
echo ""

# 1. Generate secrets
ADMIN_KEY="sk_$(openssl rand -hex 24)"

# Generate biscuit key pair using the WASM module
echo "Generating Biscuit key pair..."
BISCUIT_OUTPUT=$(node --experimental-wasm-modules --input-type=module -e "
import { KeyPair, SignatureAlgorithm } from '@biscuit-auth/biscuit-wasm';
const kp = new KeyPair(SignatureAlgorithm.Ed25519);
console.log(kp.getPrivateKey().toString());
console.log(kp.getPublicKey().toString());
" 2>/dev/null)

BISCUIT_PRIVATE_KEY=$(echo "$BISCUIT_OUTPUT" | grep '^ed25519-private/')
BISCUIT_PUBLIC_KEY=$(echo "$BISCUIT_OUTPUT" | grep '^ed25519/')

# 2. Write .env (wrangler reads .env and .dev.vars for local secrets)
cat > .env <<EOF
ADMIN_KEY=${ADMIN_KEY}
BISCUIT_PRIVATE_KEY=${BISCUIT_PRIVATE_KEY}
EOF

echo "Created .env with generated secrets"

# 3. Apply D1 migrations locally
echo "Applying D1 migrations (local)..."
npx wrangler d1 migrations apply auth-proxy-db --local 2>/dev/null || true

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Admin key: ${ADMIN_KEY}"
echo "Public key: ${BISCUIT_PUBLIC_KEY}"
echo ""
echo "Run: pnpm dev"
echo "Then: curl http://localhost:8787/"
