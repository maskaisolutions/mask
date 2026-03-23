import { getCryptoEngine } from './crypto';
import * as crypto from 'crypto';

/**
 * Manages bucket-based indexing for secure range queries.
 * Bucketing reduces the precision of a value to allow range-like searches
 * without leaking the exact value to a blind index.
 */
export class BucketManager {
  /**
   * Create a bucket for a date string.
   * @param dateStr ISO date string (YYYY-MM-DD)
   * @param granularity 'year' | 'month' | 'day'
   */
  public static dateBucket(dateStr: string, granularity: 'year' | 'month' | 'day' = 'month'): string {
    const parts = dateStr.split(/[-/]/);
    if (parts.length < 1) return "invalid_date";
    
    const year = parts[0];
    const month = parts[1] || "01";
    const day = parts[2] || "01";

    switch (granularity) {
      case 'year': return `date:y:${year}`;
      case 'month': return `date:m:${year}-${month}`;
      case 'day': return `date:d:${year}-${month}-${day}`;
      default: return `date:m:${year}-${month}`;
    }
  }

  /**
   * Create a bucket for a numeric value.
   * @param value The number to bucket
   * @param size The size of the bucket (e.g., 10 for decades)
   */
  public static numericBucket(value: number | string, size: number = 10): string {
    const val = typeof value === 'string' ? parseFloat(value) : value;
    if (isNaN(val)) return "invalid_num";
    
    const floor = Math.floor(val / size) * size;
    return `num:${size}:${floor}`;
  }

  /**
   * Generate a secure blind index for a bucket value.
   */
  public static async getBucketIndex(bucketVal: string): Promise<string> {
    const engine = await getCryptoEngine();
    const secret = await engine.getIndexSecret();
    return crypto.createHmac('sha256', secret).update(bucketVal).digest('hex');
  }
}
