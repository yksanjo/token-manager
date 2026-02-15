// Token Manager - Advanced token lifecycle management

import * as jose from 'jose';
import { v4 as uuidv4 } from 'uuid';
import {
  TokenInfo,
  TokenRotationConfig,
  TokenCacheOptions,
  RefreshCallback,
  TokenValidator,
  TokenManagerOptions,
  Logger
} from './types';

export class TokenManager {
  private currentToken: TokenInfo | null = null;
  private refreshCallback: RefreshCallback | null = null;
  private refreshBuffer: number;
  private rotation: TokenRotationConfig;
  private cache: Map<string, TokenInfo> = new Map();
  private cacheOptions: TokenCacheOptions;
  private onRefresh?: (oldToken: TokenInfo, newToken: TokenInfo) => void;
  private onError?: (error: Error) => void;
  private logger: Logger;
  private refreshAttempts: number = 0;

  constructor(logger: Logger, refreshCallback: RefreshCallback, options?: TokenManagerOptions) {
    this.logger = logger;
    this.refreshCallback = refreshCallback;
    this.refreshBuffer = options?.refreshBuffer || 60;
    this.rotation = options?.rotation || {
      enabled: true,
      rotateBeforeExpiry: 300,
      maxRefreshAttempts: 3
    };
    this.cacheOptions = options?.cache || { ttl: 3600, maxSize: 100 };
    this.onRefresh = options?.onRefresh;
    this.onError = options?.onError;
  }

  /**
   * Get current valid access token
   */
  async getAccessToken(): Promise<string> {
    if (!this.currentToken) {
      await this.refresh();
    } else if (this.needsRefresh()) {
      await this.refresh();
    }

    return this.currentToken!.accessToken;
  }

  /**
   * Set the current token
   */
  setToken(token: TokenInfo): void {
    this.currentToken = { ...token };
    this.refreshAttempts = 0;
    this.logger.info('Token set', { expiresAt: token.expiresAt });
  }

  /**
   * Clear the current token
   */
  clearToken(): void {
    this.currentToken = null;
    this.logger.info('Token cleared');
  }

  /**
   * Check if token needs refresh
   */
  needsRefresh(): boolean {
    if (!this.currentToken) return true;
    
    const now = Date.now() / 1000;
    return (this.currentToken.expiresAt - now) < this.refreshBuffer;
  }

  /**
   * Check if token is expired
   */
  isExpired(): boolean {
    if (!this.currentToken) return true;
    return Date.now() / 1000 >= this.currentToken.expiresAt;
  }

  /**
   * Get time until token expires
   */
  getTimeToExpiry(): number {
    if (!this.currentToken) return 0;
    return Math.max(0, this.currentToken.expiresAt - Date.now() / 1000);
  }

  /**
   * Force token refresh
   */
  async refresh(): Promise<TokenInfo> {
    if (!this.refreshCallback) {
      throw new Error('No refresh callback configured');
    }

    if (this.refreshAttempts >= this.rotation.maxRefreshAttempts) {
      const error = new Error('Max refresh attempts reached');
      this.onError?.(error);
      throw error;
    }

    this.refreshAttempts++;
    this.logger.info('Refreshing token', { attempt: this.refreshAttempts });

    try {
      const oldToken = this.currentToken;
      const newToken = await this.refreshCallback();
      
      this.currentToken = newToken;
      this.refreshAttempts = 0;

      if (oldToken) {
        this.onRefresh?.(oldToken, newToken);
      }

      this.logger.info('Token refreshed successfully');
      return newToken;
    } catch (error) {
      this.onError?.(error as Error);
      throw error;
    }
  }

  /**
   * Cache a token
   */
  cacheToken(key: string, token: TokenInfo): void {
    if (this.cache.size >= this.cacheOptions.maxSize) {
      const firstKey = this.cache.keys().next().value || '';
      this.cache.delete(firstKey);
    }
    this.cache.set(key, { ...token });
    this.logger.debug('Token cached', { key });
  }

  /**
   * Get cached token
   */
  getCachedToken(key: string): TokenInfo | null {
    const cached = this.cache.get(key);
    if (!cached) return null;

    if (Date.now() / 1000 >= cached.expiresAt) {
      this.cache.delete(key);
      return null;
    }

    return cached;
  }

  /**
   * Clear all cached tokens
   */
  clearCache(): void {
    this.cache.clear();
    this.logger.info('Token cache cleared');
  }

  /**
   * Create a JWT validator
   */
  static createValidator(jwksUri: string, issuer: string, audience: string): TokenValidator {
    return {
      async validate(token: string): Promise<boolean> {
        try {
          const JWKS = jose.createRemoteJWKSet(new URL(jwksUri));
          await jose.jwtVerify(token, JWKS, { issuer, audience });
          return true;
        } catch {
          return false;
        }
      },
      async getClaims(token: string): Promise<Record<string, unknown>> {
        const JWKS = jose.createRemoteJWKSet(new URL(jwksUri));
        const { payload } = await jose.jwtVerify(token, JWKS, { issuer, audience });
        return payload as Record<string, unknown>;
      }
    };
  }

  /**
   * Decode token without validation
   */
  static decodeToken(token: string): TokenInfo | null {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
      
      return {
        accessToken: token,
        tokenType: 'Bearer',
        expiresAt: payload.exp || 0,
        issuedAt: payload.iat || 0,
        claims: payload
      };
    } catch {
      return null;
    }
  }

  /**
   * Generate a secure token identifier
   */
  static generateTokenId(): string {
    return uuidv4();
  }

  /**
   * Get token info
   */
  getTokenInfo(): TokenInfo | null {
    return this.currentToken ? { ...this.currentToken } : null;
  }
}
