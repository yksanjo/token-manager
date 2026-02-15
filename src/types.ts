// Token Manager Types

export interface TokenInfo {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  tokenType: string;
  expiresAt: number;
  issuedAt: number;
  scope?: string;
  claims?: Record<string, unknown>;
}

export interface TokenRotationConfig {
  enabled: boolean;
  rotateBeforeExpiry: number; // seconds
  maxRefreshAttempts: number;
}

export interface TokenCacheOptions {
  ttl: number;
  maxSize: number;
}

export interface RefreshCallback {
  (): Promise<TokenInfo>;
}

export interface TokenValidator {
  validate(token: string): Promise<boolean>;
  getClaims(token: string): Promise<Record<string, unknown>>;
}

export interface Logger {
  info: (message: string, meta?: Record<string, unknown>) => void;
  warn: (message: string, meta?: Record<string, unknown>) => void;
  error: (message: string, meta?: Record<string, unknown>) => void;
  debug: (message: string, meta?: Record<string, unknown>) => void;
}

export interface TokenManagerOptions {
  refreshBuffer?: number;
  rotation?: TokenRotationConfig;
  cache?: TokenCacheOptions;
  onRefresh?: (oldToken: TokenInfo, newToken: TokenInfo) => void;
  onError?: (error: Error) => void;
}
