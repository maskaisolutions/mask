/**
 * NLP Worker for Piscina thread pool.
 *
 * This file runs in a worker thread and handles DistilBERT ONNX inference
 * via @huggingface/transformers. It is loaded by Piscina and MUST NOT
 * import any main-thread-only APIs.
 */

const { pipeline } = require('@huggingface/transformers');

let _pipeline = null;

/**
 * Initialize the pipeline on first call (lazy, but cached per-worker).
 */
async function initPipeline(modelName, cacheDir) {
  if (cacheDir) {
    const { env } = require('@huggingface/transformers');
    env.cacheDir = cacheDir;
  }
  
  if (!_pipeline) {
    _pipeline = await pipeline('ner', modelName, {
      progress_callback: (info) => {
        if (info.status === 'progress') {
          const pct = info.progress ? info.progress.toFixed(2) : '...';
          process.stderr.write(`[NLP Worker] Downloading ${info.file || 'model'}: ${pct}%\n`);
        }
      }
    });
  }
  return _pipeline;
}

/**
 * The default export is the function Piscina calls with each task.
 *
 * @param {{ text: string, modelName: string }} param0
 * @returns {Promise<any[]>} Raw NER results array
 */
module.exports = async function ({ text, modelName, cacheDir }) {
  const pipe = await initPipeline(modelName, cacheDir);
  const results = await pipe(text);
  return results || [];
};
