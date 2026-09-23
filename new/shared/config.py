"""Runtime configuration loader for the honeypot.

Reads all YAML files from ``new/config/`` and merges them into a
single namespace.  Values override in this order (last wins):

  honeypot.yaml  →  ssh.yaml  →  telnet.yaml  →  persona.yaml  →  limits.yaml

The result is a simple attribute‑access namespace so that
``config.ssh.port``, ``config.limits.max_sessions`` etc. work
through ``object.getattr`` without any metaclass magic.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml  # imported lazily; pip install pyyaml if missing

_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
_LOADED: bool = False
_namespace: dict = {}


def _load_yaml(name: str) -> dict:
    path = _CONFIG_DIR / name
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _namespace_merge(base: dict, override: dict) -> dict:
    """Deep merge *override* into *base* (mutates *base*)."""
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _namespace_merge(base[k], v)
        else:
            base[k] = v
    return base


def load() -> dict:
    """Load and merge all config YAML files.  Call once at startup."""
    global _LOADED, _namespace
    if _LOADED:
        return _namespace

    order = [
        "honeypot.yaml",
        "ssh.yaml",
        "telnet.yaml",
        "persona.yaml",
        "limits.yaml",
    ]

    _namespace = {}
    for name in order:
        _namespace_merge(_namespace, _load_yaml(name))

    _LOADED = True
    return _namespace


def get(key: str, default: object = None) -> object:
    """Retrieve a config value by dot‑free key (e.g. ``ssh.port``).

    The shared config namespace is flat (all YAML keys merged at top level).
    This function supports accessing values by their last-component key name,
    e.g. ``get("ssh.port")`` will find the flat key ``"port"``.
    """
    # 1. Try exact flat-key lookup first
    if key in _namespace:
        return _namespace[key]

    # 2. Try splitting dotted key and matching the last part as a flat key
    #    e.g. "ssh.port" → look up flat key "port"
    #    e.g. "limits.max_ssh_sessions" → look up flat key "max_ssh_sessions"
    parts = key.split(".", 1)
    if len(parts) == 2:
        prefix, sub_key = parts
        if sub_key in _namespace:
            return _namespace[sub_key]

    # 3. Fall back to original dotted traversal (for nested namespaces)
    parts = key.split(".")
    obj = _namespace
    for p in parts:
        if not isinstance(obj, dict) or p not in obj:
            return default
        obj = obj[p]
    return obj


def get_attr(name: str, default: object = None) -> object:
    """Attribute‑style access: ``config.get_attr('ssh.port')``."""
    return get(name, default)


# Back‑ward compatible aliases so existing ``from shared.config import ...``
# imports still work without changes to other modules.
ssh = property(lambda s: type("SSHConfig", (), {"port": get("ssh.port")})())
telnet = property(lambda s: type("TelnetConfig", (), {"port": get("telnet.port")})())
limits = property(lambda s: type("LimitsConfig", (), {
    "max_sessions": get("limits.max_sessions"),
    "session_timeout": get("limits.session_timeout"),
})())
persona = property(lambda s: type("PersonaConfig", (), {
    "hostname": get("persona.hostname"),
})())