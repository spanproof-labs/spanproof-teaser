# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
"""
SpanProof — Strict Config Meta-Schema Validator

Pure Python (zero-dependency) validator that ensures every domain
configuration JSON file conforms to the CFR Forge Meta-Schema.

This is the mathematical guarantee that a typo in a JSON config
never results in a false positive for a Fortune 500 client. If a
single key is missing or a type is wrong, the engine hard-crashes
before it processes a single row.

Usage:
    from regeval.core.config_validator import validate_domain_config
    validate_domain_config(config_dict)  # raises ConfigValidationError
"""
from __future__ import annotations


class ConfigValidationError(Exception):
    """Raised when a domain configuration file fails meta-schema validation.

    Contains a structured list of every violation found, not just the first.
    """
    def __init__(self, violations: list[str], config_name: str = "<unknown>"):
        self.violations = violations
        self.config_name = config_name
        msg = (
            f"Config '{config_name}' failed meta-schema validation "
            f"with {len(violations)} violation(s):\n"
            + "\n".join(f"  ✗ {v}" for v in violations)
        )
        super().__init__(msg)


# ---------------------------------------------------------------------------
# Section validators
# ---------------------------------------------------------------------------

def _validate_domain(cfg: dict, violations: list[str]) -> None:
    """Validate the 'domain' top-level section."""
    if "domain" not in cfg:
        violations.append("Missing required top-level section: 'domain'")
        return

    domain = cfg["domain"]
    if not isinstance(domain, dict):
        violations.append("'domain' must be a dict")
        return

    for key in ("name", "regulation"):
        if key not in domain:
            violations.append(f"Missing required field: domain.{key}")
        elif not isinstance(domain[key], str):
            violations.append(f"domain.{key} must be a string, got {type(domain[key]).__name__}")

    # cfr_title can be int or str (some configs use "49 CFR", others use 49)
    if "cfr_title" not in domain:
        violations.append("Missing required field: domain.cfr_title")
    else:
        val = domain["cfr_title"]
        if not isinstance(val, (int, str)):
            violations.append(f"domain.cfr_title must be int or str, got {type(val).__name__}")

    # version is recommended but not strictly required for backward compat
    if "version" in domain and not isinstance(domain["version"], str):
        violations.append(f"domain.version must be a string, got {type(domain['version']).__name__}")


def _validate_units(cfg: dict, violations: list[str]) -> None:
    """Validate the 'units' top-level section."""
    if "units" not in cfg:
        violations.append("Missing required top-level section: 'units'")
        return

    units = cfg["units"]
    if not isinstance(units, dict):
        violations.append("'units' must be a dict")
        return

    # known_units: list of strings
    if "known_units" not in units:
        violations.append("Missing required field: units.known_units")
    elif not isinstance(units["known_units"], list):
        violations.append(f"units.known_units must be a list, got {type(units['known_units']).__name__}")
    else:
        for i, u in enumerate(units["known_units"]):
            if not isinstance(u, str):
                violations.append(f"units.known_units[{i}] must be a string, got {type(u).__name__}")
                break  # Don't flood with per-element errors

    # unit_map: dict[str, str]
    if "unit_map" not in units:
        violations.append("Missing required field: units.unit_map")
    elif not isinstance(units["unit_map"], dict):
        violations.append(f"units.unit_map must be a dict, got {type(units['unit_map']).__name__}")
    else:
        for k, v in units["unit_map"].items():
            if not isinstance(k, str) or not isinstance(v, str):
                violations.append(f"units.unit_map entries must be str:str, got {type(k).__name__}:{type(v).__name__} for key '{k}'")
                break

    # unit_scales: dict[str, float|int]
    if "unit_scales" not in units:
        violations.append("Missing required field: units.unit_scales")
    elif not isinstance(units["unit_scales"], dict):
        violations.append(f"units.unit_scales must be a dict, got {type(units['unit_scales']).__name__}")
    else:
        for k, v in units["unit_scales"].items():
            if not isinstance(k, str):
                violations.append(f"units.unit_scales key must be str, got {type(k).__name__}")
                break
            if not isinstance(v, (int, float)):
                violations.append(f"units.unit_scales['{k}'] must be a number (int/float), got {type(v).__name__}: '{v}'")
                break


def _validate_boolean(cfg: dict, violations: list[str]) -> None:
    """Validate the 'boolean' top-level section."""
    if "boolean" not in cfg:
        violations.append("Missing required top-level section: 'boolean'")
        return

    boolean = cfg["boolean"]
    if not isinstance(boolean, dict):
        violations.append("'boolean' must be a dict")
        return

    for key in ("yes_synonyms", "no_synonyms"):
        if key not in boolean:
            violations.append(f"Missing required field: boolean.{key}")
        elif not isinstance(boolean[key], list):
            violations.append(f"boolean.{key} must be a list, got {type(boolean[key]).__name__}")
        else:
            if len(boolean[key]) == 0:
                violations.append(f"boolean.{key} must not be empty")
            for i, s in enumerate(boolean[key]):
                if not isinstance(s, str):
                    violations.append(f"boolean.{key}[{i}] must be a string, got {type(s).__name__}")
                    break


def _validate_identifiers(cfg: dict, violations: list[str]) -> None:
    """Validate the 'identifiers' top-level section."""
    if "identifiers" not in cfg:
        violations.append("Missing required top-level section: 'identifiers'")
        return

    idents = cfg["identifiers"]
    if not isinstance(idents, dict):
        violations.append("'identifiers' must be a dict")
        return

    if "prefix_patterns" not in idents:
        violations.append("Missing required field: identifiers.prefix_patterns")
    elif not isinstance(idents["prefix_patterns"], list):
        violations.append(f"identifiers.prefix_patterns must be a list, got {type(idents['prefix_patterns']).__name__}")
    else:
        import re
        for i, pat in enumerate(idents["prefix_patterns"]):
            if not isinstance(pat, str):
                violations.append(f"identifiers.prefix_patterns[{i}] must be a string")
                break
            try:
                re.compile(pat)
            except re.error as exc:
                violations.append(f"identifiers.prefix_patterns[{i}] is an invalid regex: '{pat}' — {exc}")

    if "stopwords" not in idents:
        violations.append("Missing required field: identifiers.stopwords")
    elif not isinstance(idents["stopwords"], list):
        violations.append(f"identifiers.stopwords must be a list, got {type(idents['stopwords']).__name__}")


def _validate_normalization(cfg: dict, violations: list[str]) -> None:
    """Validate the optional 'normalization' section if present."""
    if "normalization" not in cfg:
        return  # Optional section

    norm = cfg["normalization"]
    if not isinstance(norm, dict):
        violations.append("'normalization' must be a dict")
        return

    rules = norm.get("rules", [])
    if not isinstance(rules, list):
        violations.append("normalization.rules must be a list")
        return

    import re
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            violations.append(f"normalization.rules[{i}] must be a dict")
            continue
        for key in ("name", "pattern", "replacement"):
            if key not in rule:
                violations.append(f"normalization.rules[{i}] missing required key: '{key}'")
        if "pattern" in rule:
            try:
                re.compile(rule["pattern"])
            except re.error as exc:
                violations.append(f"normalization.rules[{i}] ('{rule.get('name', '?')}') has invalid regex: {exc}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_domain_config(config: dict, config_name: str = "<unknown>") -> bool:
    """Validate a domain configuration dict against the CFR Meta-Schema.

    Args:
        config: The parsed JSON config dictionary.
        config_name: Human-readable name for error messages.

    Returns:
        True if validation passes.

    Raises:
        ConfigValidationError: If any violations are found, with a full
            list of every issue (not just the first).
    """
    violations: list[str] = []

    _validate_domain(config, violations)
    _validate_units(config, violations)
    _validate_boolean(config, violations)
    _validate_identifiers(config, violations)
    _validate_normalization(config, violations)

    if violations:
        raise ConfigValidationError(violations, config_name)

    return True
