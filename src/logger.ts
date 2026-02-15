import winston from 'winston';
import { Logger } from './types';

export type { Logger };

export function createLogger(options?: { level?: string; silent?: boolean }): Logger {
  const logger = winston.createLogger({
    level: options?.level || 'info',
    silent: options?.silent || false,
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    defaultMeta: { service: 'token-manager' },
    transports: [new winston.transports.Console({ format: winston.format.simple() })]
  });

  return {
    info: (msg, meta) => logger.info(msg, meta),
    warn: (msg, meta) => logger.warn(msg, meta),
    error: (msg, meta) => logger.error(msg, meta),
    debug: (msg, meta) => logger.debug(msg, meta)
  };
}

export const defaultLogger = createLogger();
