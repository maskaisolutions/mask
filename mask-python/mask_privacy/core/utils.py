"""
Utility functions for the Mask SDK.

Provides shared recursive data structures traversal algorithms used by the
various framework integration hooks (LangChain, LlamaIndex, ADK) to find
and intercept tokens/PII hidden deep inside nested dictionaries, lists,
and Pydantic models.
"""

from typing import Any, List, Dict, Optional, Tuple, Union

from mask_privacy.core.vault import _decode_lenient, detokenize_text
from mask_privacy.core.fpe import looks_like_token
from mask_privacy.core.scanner import get_scanner


MAX_DEPTH = 100

def deep_decode(obj: Any) -> Any:
    """Walk *obj* iteratively and detokenise all Mask tokens found."""
    return _deep_walk_iterative(obj, 'decode')

def deep_encode_pii(obj: Any) -> Any:
    """Walk *obj* and tokenise PII using the configured scanner."""
    return _deep_walk_iterative(obj, 'encode')

def _deep_walk_iterative(root: Any, op: str) -> Any:
    """Internal iterative walker to prevent stack overflow and ensure non-mutation."""
    if root is None or (not isinstance(root, (str, dict, list, tuple)) and not _is_pydantic(root)):
        return root

    # Re-importing inside for safety against circulars if needed, 
    # but using top-level imports where possible.
    from mask_privacy.core.vault import detokenize_text
    from mask_privacy.core.fpe import looks_like_token
    from mask_privacy.core.scanner import get_scanner

    # Top-level string optimization
    if isinstance(root, str):
        if op == 'decode':
            return detokenize_text(root)
        if looks_like_token(root):
            return root
        return get_scanner().scan_and_tokenize(root)

    # Rebuild the structure iteratively
    # result_holder acts as a root container to safely handle the root result.
    result_holder: List[Any] = [None]
    # Stack: (source_obj, target_container, key_or_index, depth)
    stack: List[Tuple[Any, Any, Union[str, int], int]] = [(root, result_holder, 0, 0)]
    
    # Store tasks for post-processing (Tuples and Pydantic models)
    post_process_tasks = [] 

    while stack:
        source, target, key, depth = stack.pop()
        
        if depth > MAX_DEPTH:
            target[key] = source 
            continue

        if isinstance(source, str):
            if op == 'decode':
                target[key] = detokenize_text(source)
            else:
                target[key] = source if looks_like_token(source) else get_scanner().scan_and_tokenize(source)
        
        elif isinstance(source, dict):
            new_dict: Dict[Any, Any] = {}
            target[key] = new_dict
            for k, v in source.items():
                stack.append((v, new_dict, k, depth + 1))
        
        elif isinstance(source, (list, tuple)):
            new_list: List[Any] = [None] * len(source)
            target[key] = new_list
            if isinstance(source, tuple):
                post_process_tasks.append((new_list, tuple, target, key))
            for i, v in enumerate(source):
                stack.append((v, new_list, i, depth + 1))
        
        elif _is_pydantic(source):
            new_dict = {}
            target[key] = new_dict
            fields = getattr(source, "__fields__", getattr(source, "model_fields", {}))
            for field_name in fields:
                v = getattr(source, field_name, None)
                stack.append((v, new_dict, field_name, depth + 1))
            post_process_tasks.append((new_dict, source.__class__, target, key))
        
        else:
            target[key] = source

    # Process tasks in reverse order (bottom-up)
    for container, original_type, parent, key in reversed(post_process_tasks):
        if original_type is tuple:
            parent[key] = tuple(container)
        else:
            # original_type is a Pydantic model class
            parent[key] = original_type(**container)

    return result_holder[0]

def _is_pydantic(obj: Any) -> bool:
    return hasattr(obj, "dict") or hasattr(obj, "model_dump")
