/**
 * Local Transformers-based NER Scanner for Mask SDK.
 * 
 * Uses @huggingface/transformers via a Piscina worker pool to provide
 * state-of-the-art PII detection (Names, Locations, Organizations) entirely
 * on the local machine via ONNX Runtime — without blocking the Node.js event loop.
 */

import { BaseScanner } from './scanner';
import { looksLikeToken } from './fpe';
import { withTimeout } from './timeout';
import { MaskNLPTimeout } from './exceptions';
import * as path from 'path';
import * as os from 'os';
import { config } from '../config';

let Piscina: any;
try {
  Piscina = require('piscina');
} catch {
  // Will be caught at initialization time with a clear error
}

export class LocalTransformersScanner extends BaseScanner {
  private _pool: any = null;
  private _modelName: string;
  private _warmupPromise: Promise<void> | null = null;

  constructor(modelName?: string) {
    super();
    if (modelName) {
      this._modelName = modelName;
    } else if (config.MASK_NLP_MODEL) {
      this._modelName = config.MASK_NLP_MODEL;
    } else {
      const langs = config.MASK_LANGUAGES.split(',').map(l => l.trim().toLowerCase());
      const needsMultilingual = langs.some(l => l !== 'en');
      if (needsMultilingual) {
        this._modelName = 'Xenova/bert-base-multilingual-cased-ner-hrl';
      } else {
        this._modelName = 'Xenova/distilbert-base-uncased-ner-simple';
      }
    }
    // Eagerly start the worker pool and pre-warm the model
    this._warmupPromise = this._initPool();
  }

  /**
   * Initialize the Piscina worker pool and pre-warm the ONNX model.
   * The model is loaded eagerly at construction time to avoid P99 latency
   * spikes on the first user request.
   */
  private async _initPool(): Promise<void> {
    if (!Piscina) {
      throw new Error(
        "Missing required dependency 'piscina'. " +
        "Please run 'npm install piscina' to use the LocalTransformersScanner."
      );
    }

    if (!this._pool) {
      const workerPath = path.resolve(__dirname, 'nlp_worker.js');
      const maxThreads = Math.max(1, Math.min(os.cpus().length - 1, 4));

      this._pool = new Piscina({
        filename: workerPath,
        maxThreads,
        minThreads: 1,
      });

      // Pre-warm: run a dummy inference to force model download/load
      const cacheDir = config.MASK_MODEL_CACHE_DIR;
      console.info(`[NLP Pool] Pre-warming ${maxThreads} worker(s) with model: ${this._modelName}${cacheDir ? ` (cache: ${cacheDir})` : ''}`);
      try {
        await this._pool.run({ text: 'warmup', modelName: this._modelName, cacheDir });
        console.info('[NLP Pool] Pre-warm complete. Workers are ready.');
      } catch (e) {
        console.warn(`[NLP Pool] Pre-warm failed (will retry on first real request): ${e}`);
      }
    }
  }

  /**
   * Map Transformer entity types to Mask internal entity types.
   */
  private _mapEntityType(type: string): string {
    const mapping: Record<string, string> = {
      'PER': 'PERSON',
      'LOC': 'LOCATION',
      'ORG': 'ORGANIZATION',
      'MISC': 'MISCELLANEOUS'
    };
    const baseType = type.split('-').pop() || type;
    return mapping[baseType] || baseType;
  }

  protected async _tier2Nlp(
    text: string,
    encodeFn: (val: string) => Promise<string>,
    boostEntities: Set<string>,
    aggressive: boolean,
    confidenceThreshold: number,
  ): Promise<[string, any[]]> {
    if (!text || text.trim().length === 0) return [text, []];

    // Ensure pool is initialized (waits for pre-warm if still in progress)
    await this._warmupPromise;

    const timeoutSec = config.MASK_NLP_TIMEOUT_SECONDS;
    const timeoutMs = timeoutSec * 1000;

    try {
      const ac = new AbortController();
      const cacheDir = config.MASK_MODEL_CACHE_DIR;
      const results = await withTimeout(
        this._pool.run({ text, modelName: this._modelName, cacheDir }, { signal: ac.signal }),
        timeoutMs,
        ac
      ) as any[];
      if (!results || results.length === 0) return [text, []];

      const entities: any[] = [];
      const entityResults = results.filter((r: any) => r.entity !== 'O' && r.score > 0.3);
      const mergedResults = this._mergeResultsWithOffsets(entityResults, text);

      for (const r of mergedResults) {
        const start = r.start;
        const end = r.end;
        const val = text.slice(start, end);

        const entityType = this._mapEntityType(r.entity);
        let confidence = r.score || 0.7;

        if (aggressive || boostEntities.has(entityType.toLowerCase().replace(/_/g, " "))) {
          confidence = Math.min(1.0, confidence + 0.2);
        }
        
        if (confidence >= confidenceThreshold && !looksLikeToken(val) && val.length > 1) {
          const token = await encodeFn(val);
          entities.push({
            type: entityType,
            value: val,
            method: "nlp-local",
            confidence: confidence,
            masked_value: token,
            _start: start,
            _end: end,
          });
        }
      }

      // Sort and replace
      let maskedText = text;
      const sortedEntities = [...entities].sort((a, b) => b._start - a._start);
      for (const entity of sortedEntities) {
        maskedText = maskedText.slice(0, entity._start) + entity.masked_value + maskedText.slice(entity._end);
      }

      return [maskedText, entities]; 
    } catch (e) {
      if (e instanceof MaskNLPTimeout) {
        console.warn(`Local NLP scan timed out after ${timeoutSec}s. Skipping Tier 2.`);
        return [text, []];
      }
      console.error(`Local NLP scan failed: ${e}`);
      return [text, []];
    }
  }

  /**
   * Merges sub-tokens and entities of the same type while precisely tracking 
   * offsets in the original text.
   */
  private _mergeResultsWithOffsets(results: any[], originalText: string): any[] {
    if (results.length === 0) return [];

    const merged: any[] = [];
    let current: any = null;

    for (const r of results) {
      const isSubToken = r.word.startsWith('##');
      const rBaseType = r.entity.split('-').pop();
      const currentBaseType = current ? current.entity.split('-').pop() : null;
      const sameType = rBaseType === currentBaseType;

      // Handle cases where start/end are missing (rare but possible in some models)
      if (r.start === undefined || r.end === undefined) {
          const searchIdx = current ? current.end : 0;
          const word = isSubToken ? r.word.slice(2) : r.word;
          const found = originalText.indexOf(word, searchIdx);
          if (found !== -1) {
              r.start = found;
              r.end = found + word.length;
          }
      }

      if (current && (isSubToken || sameType)) {
        const gap = r.start - current.end;
        if (isSubToken || gap <= 1) {
          current.end = Math.max(current.end, r.end);
          current.score = Math.min(current.score, r.score);
          current.word = originalText.slice(current.start, current.end);
        } else {
          merged.push(current);
          current = { ...r };
        }
      } else {
        if (current) merged.push(current);
        current = { ...r };
      }
    }
    if (current) merged.push(current);
    return merged;
  }

  /**
   * Gracefully shut down the worker pool.
   * Call this during application shutdown to prevent the Node.js process from hanging.
   */
  async close(): Promise<void> {
    if (this._pool) {
      await this._pool.destroy();
      this._pool = null;
      this._warmupPromise = null;
      console.info('[NLP Pool] Worker pool destroyed.');
    }
  }
}
