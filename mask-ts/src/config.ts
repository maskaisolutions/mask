/**
 * Mask Privacy SDK Configuration.
 * Centralizes all environment-based settings with detailed documentation.
 */

import * as process from 'process';
import * as path from 'path';
import * as os from 'os';

/** Helper to parse boolean environment variables. */
const getEnvBool = (name: string, defaultValue: boolean = false): boolean => {
  const val = process.env[name];
  if (val === undefined) return defaultValue;
  return ['true', '1', 'yes'].includes(val.toLowerCase());
};

/** Helper to parse integer environment variables. */
const getEnvInt = (name: string, defaultValue: number): number => {
  const val = process.env[name];
  if (val === undefined) return defaultValue;
  const parsed = parseInt(val, 10);
  return isNaN(parsed) ? defaultValue : parsed;
};

/** Helper to parse float environment variables. */
const getEnvFloat = (name: string, defaultValue: number): number => {
  const val = process.env[name];
  if (val === undefined) return defaultValue;
  const parsed = parseFloat(val);
  return isNaN(parsed) ? defaultValue : parsed;
};

export const config = {
  // --- GENERAL ENVIRONMENT ---
  get MASK_ENV() { return (process.env.MASK_ENV || 'production').toLowerCase(); },
  get MASK_DEV_MODE() { return getEnvBool('MASK_DEV_MODE', false); },
  get MASK_LOG_LEVEL() { return (process.env.MASK_LOG_LEVEL || 'info').toLowerCase(); },

  // --- COMPLIANCE & PRIVACY (Bijective) ---
  get MASK_TENANT_ID() { return process.env.MASK_TENANT_ID || 'global-default-tenant'; },
  get MASK_SALT_ROTATION() { return (process.env.MASK_SALT_ROTATION || 'NONE').toUpperCase(); },
  get MASK_BIJECTIVE_MODE() { return getEnvBool('MASK_BIJECTIVE_MODE', true); },

  // --- SECURITY & CRYPTOGRAPHY ---
  get MASK_ENCRYPTION_KEY() { return process.env.MASK_ENCRYPTION_KEY || null; },
  get MASK_MASTER_KEY() { 
    return process.env.MASK_MASTER_KEY || process.env.MASK_ENCRYPTION_KEY || ''; 
  },
  get MASK_ENCRYPTED_KEY() { return process.env.MASK_ENCRYPTED_KEY || null; },
  get MASK_STRICT_PROD() { return getEnvBool('MASK_STRICT_PROD', false); },
  get MASK_BLIND_INDEX_SALT() { return process.env.MASK_BLIND_INDEX_SALT || "mask-blind-index"; },
  get VAULT_TOKEN() { return process.env.VAULT_TOKEN || null; },

  // --- VAULT & STORAGE ---
  get MASK_VAULT_TYPE() { return (process.env.MASK_VAULT_TYPE || 'memory').toLowerCase(); },
  get MASK_FAIL_STRATEGY() { return (process.env.MASK_FAIL_STRATEGY || "").toLowerCase(); },
  get MASK_VAULT_TTL() { return getEnvInt('MASK_VAULT_TTL', 600); },
  get MASK_VAULT_CLEANUP_FREQUENCY() { return getEnvFloat('MASK_VAULT_CLEANUP_FREQUENCY', 0.01); },

  // --- BACKEND CONNECTIONS ---
  get MASK_REDIS_URL() { return process.env.MASK_REDIS_URL || "redis://localhost:6379/0"; },
  get MASK_DYNAMODB_REGION() { return process.env.MASK_DYNAMODB_REGION || "us-east-1"; },
  get MASK_DYNAMODB_TABLE() { return process.env.MASK_DYNAMODB_TABLE || "mask-vault"; },
  get MASK_DYNAMODB_MAX_SOCKETS() { return getEnvInt('MASK_DYNAMODB_MAX_SOCKETS', 50); },
  get MASK_MEMCACHED_HOST() { return process.env.MASK_MEMCACHED_HOST || "localhost"; },
  get MASK_MEMCACHED_PORT() { return getEnvInt('MASK_MEMCACHED_PORT', 11211); },

  // --- NLP & DETECTION ---
  get MASK_LANGUAGES() { return process.env.MASK_LANGUAGES || "en"; },
  get MASK_NLP_MODEL() { return process.env.MASK_NLP_MODEL || null; },
  get MASK_NLP_MAX_WORKERS() { return getEnvInt('MASK_NLP_MAX_WORKERS', 4); },
  get MASK_NLP_TIMEOUT_SECONDS() { return getEnvInt('MASK_NLP_TIMEOUT_SECONDS', 60); },
  get MASK_SCANNER_TYPE() { return (process.env.MASK_SCANNER_TYPE || 'local').toLowerCase(); },
  get MASK_SCANNER_URL() { return process.env.MASK_SCANNER_URL || "http://localhost:5001/analyze"; },
  get MASK_MODEL_CACHE_DIR() { return process.env.MASK_MODEL_CACHE_DIR || path.join(os.homedir(), '.cache', 'mask'); },

  // --- TELEMETRY & AUDIT ---
  get MASK_AUDIT_LOG_STRICT() { return getEnvBool('MASK_AUDIT_LOG_STRICT', false); },
  get MASK_AUDIT_MAX_BUFFER_SIZE() { return getEnvInt('MASK_AUDIT_MAX_BUFFER_SIZE', 5000); }
};
