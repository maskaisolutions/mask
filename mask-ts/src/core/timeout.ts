/**
 * Timeout utility for Promises.
 */

import { MaskNLPTimeout } from './exceptions';

/**
 * Rejects with a MaskNLPTimeout error after a specified duration in milliseconds.
 */
export function withTimeout<T>(promise: Promise<T>, ms: number, controller?: AbortController): Promise<T> {
  let timeoutId: NodeJS.Timeout;

  const timeoutPromise = new Promise<T>((_, reject) => {
    timeoutId = setTimeout(() => {
      const err = new MaskNLPTimeout(`Operation timed out after ${ms}ms`);
      if (controller) {
        controller.abort(err);
      }
      reject(err);
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
