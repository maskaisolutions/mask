/**
 * Remote PII Scanner — Offloads NLP to a centralized Presidio server.
 */

import { BaseScanner } from './scanner';
import { looksLikeToken } from './fpe_utils';
import { config } from '../config';
import { getLogger } from '../telemetry/audit_logger';

const logger = getLogger('mask.scanner.remote');

export class RemoteScanner extends BaseScanner {
  private _url: string;

  constructor(url?: string) {
    super();
    this._url = url || config.MASK_SCANNER_URL;
    logger.info(`Using RemoteScanner at ${this._url}`);
  }

  protected async _tier2Nlp(
    text: string,
    encodeFn: (val: string) => Promise<string>,
    boostEntities: Set<string>,
    aggressive: boolean,
    confidenceThreshold: number,
  ): Promise<[string, any[]]> {
    let axios;
    try {
        axios = require('axios');
    } catch (e) {
        logger.error("axios is required for RemoteScanner. Install it with: npm install axios");
        return [text, []];
    }

    const entities: any[] = [];
    let results: any[] = [];

    try {
        const response = await axios.post(this._url, {
            text,
            language: "en"
        }, {
            timeout: config.MASK_NLP_TIMEOUT_SECONDS * 1000
        });
        results = response.data;
    } catch (e: any) {
        logger.error(`Remote NLP scan failed: ${e.message}`);
        return [text, []];
    }

    if (!Array.isArray(results)) {
        logger.warn("Remote NLP scan returned invalid data format (expected array)");
        return [text, []];
    }

    let maskedText = text;
    // Process from right-to-left to keep offsets valid
    const sortedResults = [...results].sort((a, b) => (b.start || 0) - (a.start || 0));

    for (const r of sortedResults) {
        const start = r.start;
        const end = r.end;
        const entityType = r.entity_type;
        let confidence = r.score || 0.7;

        if (aggressive || boostEntities.has(entityType.toLowerCase().replace(/_/g, " "))) {
            confidence = Math.min(1.0, confidence + 0.2);
        }

        const val = text.slice(start, end);
        if (confidence >= confidenceThreshold && !looksLikeToken(val)) {
            const token = await encodeFn(val);
            maskedText = maskedText.slice(0, start) + token + maskedText.slice(end);
            entities.push({
                type: entityType,
                value: val,
                method: "nlp-remote",
                confidence: confidence,
                masked_value: token,
            });
        }
    }

    return [maskedText, entities];
  }
}
