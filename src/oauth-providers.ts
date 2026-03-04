export interface KnownOAuthProvider {
  authorizeUrl: string
  tokenUrl: string
  scopes: string
  authConfig: Record<string, string>
}

export const KNOWN_OAUTH_PROVIDERS: Record<string, KnownOAuthProvider> = {
  'api.github.com': {
    authorizeUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    scopes: 'repo read:user',
    authConfig: {
      token_accept: 'application/json',
      identity_url: 'https://api.github.com/user',
      identity_path: 'login',
    },
  },
  'api.linear.app': {
    authorizeUrl: 'https://linear.app/oauth/authorize',
    tokenUrl: 'https://api.linear.app/oauth/token',
    scopes: 'read',
    authConfig: {
      token_accept: 'application/json',
      identity_url: 'https://api.linear.app/graphql',
      identity_method: 'POST',
      identity_body: '{"query":"query { viewer { email } }"}',
      identity_path: 'data.viewer.email',
    },
  },
  'api.notion.com': {
    authorizeUrl: 'https://api.notion.com/v1/oauth/authorize',
    tokenUrl: 'https://api.notion.com/v1/oauth/token',
    scopes: '',
    authConfig: {
      token_accept: 'application/json',
    },
  },
  'slack.com': {
    authorizeUrl: 'https://slack.com/oauth/v2/authorize',
    tokenUrl: 'https://slack.com/api/oauth.v2.access',
    scopes: 'users:read',
    authConfig: {
      token_accept: 'application/json',
    },
  },
  'www.googleapis.com': {
    authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    scopes: 'openid email profile',
    authConfig: {
      token_accept: 'application/json',
    },
  },
  'accounts.google.com': {
    authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    scopes: 'openid email profile',
    authConfig: {
      token_accept: 'application/json',
    },
  },
}

export function getKnownOAuthProvider(service: string): KnownOAuthProvider | null {
  if (KNOWN_OAUTH_PROVIDERS[service]) {
    return KNOWN_OAUTH_PROVIDERS[service]
  }

  if (service.endsWith('.googleapis.com')) {
    return KNOWN_OAUTH_PROVIDERS['www.googleapis.com']
  }

  if (service === 'github.com') {
    return KNOWN_OAUTH_PROVIDERS['api.github.com']
  }

  return null
}
