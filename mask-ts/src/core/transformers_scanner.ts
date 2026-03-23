/**
 * Local Transformers-based NER Scanner for Mask SDK.
 * 
 * Uses @huggingface/transformers to provide state-of-the-art PII detection
 * (Names, Locations, Organizations) entirely on the local machine via ONNX Runtime.
 */

import { BaseScanner } from './scanner';
import { pipeline } from '@huggingface/transformers';
import { looksLikeToken } from './fpe';
import { withTimeout } from './timeout';
import { MaskNLPTimeout } from './exceptions';

export class LocalTransformersScanner extends BaseScanner {
  private _pipeline: any = null;
  private _modelName: string;

  constructor(modelName: string = 'Xenova/distilbert-base-uncased-ner-simple') {
    super();
    this._modelName = modelName;
  }

  /**
   * Initialize the Transformers pipeline.
   * This will download the model on the first run (cached thereafter).
   */
  private async _initPipeline() {
    if (!this._pipeline) {
      console.info(`Initializing local NLP model: ${this._modelName}...`);
      this._pipeline = await pipeline('ner', this._modelName, {
        progress_callback: (info: any) => {
          if (info.status === 'progress') {
            const pct = info.progress ? info.progress.toFixed(2) : '...';
            console.info(`[NLP Model] Downloading ${info.file || 'model'}: ${pct}%`);
          } else if (info.status === 'ready') {
            console.info(`[NLP Model] ${info.file || 'Component'} is ready.`);
          }
        }
      });
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

    await this._initPipeline();

    const timeoutSec = parseInt(process.env.MASK_NLP_TIMEOUT_SECONDS || "30");
    const timeoutMs = timeoutSec * 1000;

    try {
      const results = await withTimeout(this._pipeline(text), timeoutMs) as any[];
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
        // If types match or it's a sub-token, and they are reasonably close, merge.
        // We allow a small gap (e.g. 1 char for a space) if types match.
        const gap = r.start - current.end;
        if (isSubToken || gap <= 1) {
          current.end = Math.max(current.end, r.end);
          current.score = Math.min(current.score, r.score);
          // Update word only if needed for debugging, the offsets are what matter
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
}
