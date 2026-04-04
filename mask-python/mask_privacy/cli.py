"""
CLI tool for Mask Privacy SDK.
Provides utilities for model management and environment pre-warming.
"""

import os
import sys
import argparse
import logging
from typing import List
from mask_privacy import config

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("mask.cli")

def cache_models(languages: List[str], engine: str, cache_dir: str):
    """Download models for the specified languages and engines."""
    logger.info(f"Starting model pre-caching for engine: {engine}")
    logger.info(f"Languages: {', '.join(languages)}")
    logger.info(f"Cache Directory: {cache_dir}")

    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir, exist_ok=True)

    if engine == "spacy":
        try:
            import spacy
            for lang in languages:
                model_map = {
                    "en": "en_core_web_sm",
                    "es": "es_core_news_sm",
                }
                model_name = model_map.get(lang)
                if model_name:
                    logger.info(f"Downloading spaCy model: {model_name}")
                    spacy.cli.download(model_name)
                else:
                    logger.warning(f"Unsupported language for spaCy: {lang}. Supported: en, es")
        except ImportError:
            logger.error("spaCy not installed. Run 'pip install mask-privacy[spacy]'")
            sys.exit(1)

    elif engine == "transformers":
        try:
            from transformers import AutoTokenizer, AutoModelForTokenClassification
            
            # Determine which model to cache based on language
            needs_multilingual = any(l == "es" for l in languages)
            model_name = "Xenova/bert-base-multilingual-cased-ner-hrl" if needs_multilingual else "Xenova/distilbert-base-uncased-ner-simple"
            
            # Override if MASK_NLP_MODEL is set
            model_name = os.environ.get("MASK_NLP_MODEL", model_name)
            
            logger.info(f"Downloading Transformers model: {model_name}")
            AutoTokenizer.from_pretrained(model_name, cache_dir=cache_dir)
            AutoModelForTokenClassification.from_pretrained(model_name, cache_dir=cache_dir)
            logger.info("Transformers model cached successfully.")
            
        except ImportError:
            logger.error("transformers not installed. Run 'pip install transformers'")
            sys.exit(1)
    
    else:
        logger.error(f"Unknown engine: {engine}. Supported: 'spacy', 'transformers'")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Mask Privacy SDK Command Line Interface")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # cache-models command
    cache_parser = subparsers.add_parser("cache-models", help="Pre-download NLP models to local cache")
    cache_parser.add_argument(
        "--languages", 
        type=str, 
        default=config.MASK_LANGUAGES,
        help="Comma-separated list of languages to cache (default: en)"
    )
    cache_parser.add_argument(
        "--engine", 
        type=str, 
        default=config.MASK_NLP_ENGINE,
        help="NLP engine to cache models for (spacy, transformers)"
    )
    cache_parser.add_argument(
        "--cache-dir", 
        type=str, 
        default=config.MASK_MODEL_CACHE_DIR,
        help="Directory to save models"
    )

    args = parser.parse_args()

    if args.command == "cache-models":
        langs = [l.strip().lower() for l in args.languages.split(",")]
        cache_models(langs, args.engine.lower(), args.cache_dir)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
