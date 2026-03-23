/**
 * Timeout utility for Promises.
 */

import { MaskNLPTimeout } from './exceptions';

/**
 * Rejects with a MaskNLPTimeout error after a specified duration in milliseconds.
 */
export function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timeoutId: NodeJS.Timeout;

  const timeoutPromise = new Promise<T>((_, reject) => {
    timeoutId = setTimeout(() => {
      reject(new MaskNLPTimeout(`Operation timed out after ${ms}ms`));
    }, ms);
    if (timeoutId && (timeoutId as any).unref) {
      (timeoutId as any).unref();
    }
  });

  return Promise.race([
    promise,
    timeoutPromise
  ]).finally(() => {
    clearTimeout(timeoutId);
  });
}
