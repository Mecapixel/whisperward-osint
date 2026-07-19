"""
core/registry.py
WhisperWard Core — Specialization Registry
Pixora Inc. | Roadmap Phase 1

The registration seam between the reusable investigation core and the
specialization modules. A specialization declares its capabilities here at
import time; the core resolves them here at use time. The core never
imports a specialization directly.

Two resolution paths, in order:

1. Explicit registration. A specialization calls register_classifier() when
   it is imported (see modules/child_safety/__init__.py).
2. Lazy default. If nothing has registered, the default dotted path below
   is imported on first use. This preserves the platform's existing
   behavior — the child-safety grooming classifier remains the default —
   while keeping the import direction one-way: the path is data, not an
   import statement, so core carries no static dependency on any module.

Signal and indicator declarations registered here are additive metadata in
Phase 1; the risk engine's weighting is unchanged. Phase 2 builds the
confidence engine on top of these declarations.
"""

from __future__ import annotations

import importlib
from typing import Callable, Optional

from core.contracts import BehavioralClassifier

# The platform default. Data, not an import: resolved lazily on first use
# only if no specialization has registered a classifier explicitly.
DEFAULT_CLASSIFIER_PATH = (
    "modules.child_safety.behavioral_classifier:GroomingClassifier"
)

_classifier_factories: dict[str, Callable[[], BehavioralClassifier]] = {}
_default_classifier_name: Optional[str] = None
_signal_declarations: dict[str, dict] = {}


def register_classifier(
    name: str,
    factory: Callable[[], BehavioralClassifier],
    make_default: bool = True,
) -> None:
    """Register a behavioral classifier factory under a specialization name."""
    global _default_classifier_name
    _classifier_factories[name] = factory
    if make_default or _default_classifier_name is None:
        _default_classifier_name = name


def register_signals(specialization: str, signals: dict) -> None:
    """Record the signal and indicator taxonomy a specialization provides.

    Phase 1: declarative metadata only, surfaced for documentation and
    review. Phase 2 wires these declarations into the confidence engine.
    """
    _signal_declarations[specialization] = dict(signals)


def declared_signals() -> dict[str, dict]:
    """Return every specialization's declared signal taxonomy."""
    return {k: dict(v) for k, v in _signal_declarations.items()}


def get_classifier(name: Optional[str] = None) -> BehavioralClassifier:
    """Resolve a classifier instance by name, or the platform default.

    Resolution order: an explicitly registered factory, then the lazy
    default dotted path. Raises LookupError if a requested name is unknown.
    """
    key = name or _default_classifier_name
    if key is not None and key in _classifier_factories:
        return _classifier_factories[key]()
    if name is not None:
        raise LookupError(f"No classifier registered under name: {name!r}")
    module_path, _, attr = DEFAULT_CLASSIFIER_PATH.partition(":")
    module = importlib.import_module(module_path)
    factory = getattr(module, attr)
    return factory()


def reset() -> None:
    """Clear all registrations. Intended for tests."""
    global _default_classifier_name
    _classifier_factories.clear()
    _signal_declarations.clear()
    _default_classifier_name = None
