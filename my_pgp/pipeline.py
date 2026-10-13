"""Composable reversible cipher pipeline."""
from __future__ import annotations
import json
from .aes import aes_bytes
from .classical import caesar, reverse_bytes, vigenere
from .encoding import EncodingError, hex_to_bytes
from .xor_cipher import xor_bytes

SUPPORTED = {"xor", "aes", "caesar", "vigenere", "reverse"}

def _key(step: dict) -> bytes:
    value = str(step.get("key", ""))
    return hex_to_bytes(value)

def apply_step(data: bytes, step: dict, decrypt: bool = False) -> bytes:
    algorithm = str(step.get("algorithm", "")).lower()
    if algorithm not in SUPPORTED:
        raise EncodingError(f"unsupported pipeline algorithm: {algorithm}")
    if algorithm == "xor":
        return xor_bytes(data, _key(step), bool(step.get("block_mode", False)), decrypt)
    if algorithm == "aes":
        return aes_bytes(data, _key(step), decrypt, bool(step.get("block_mode", False)), bool(step.get("project_format", False)))
    if algorithm == "caesar":
        return caesar(data, int(step.get("shift", 0)), decrypt)
    if algorithm == "vigenere":
        return vigenere(data, _key(step), decrypt)
    return reverse_bytes(data, decrypt)

def run_pipeline(data: bytes, steps: list[dict], decrypt: bool = False) -> bytes:
    if not isinstance(steps, list) or not steps:
        raise EncodingError("pipeline must contain at least one step")
    ordered = reversed(steps) if decrypt else steps
    for step in ordered:
        if not isinstance(step, dict):
            raise EncodingError("each pipeline step must be an object")
        data = apply_step(data, step, decrypt)
    return data

def parse_pipeline(value: str) -> list[dict]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise EncodingError("pipeline must be valid JSON") from exc
    if not isinstance(parsed, list):
        raise EncodingError("pipeline JSON must be an array")
    return parsed
