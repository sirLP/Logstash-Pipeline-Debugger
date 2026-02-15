"""Compatibility shim that exposes `LogstashParser` and `parse_config_to_tree`.

This module imports the implementations from the legacy top-level
`logstash_parser.py` to avoid duplicating large code during a gradual
refactor.
"""
try:
    # Prefer the installed/package version if available
    from logstash_parser import LogstashParser, parse_config_to_tree  # type: ignore
except Exception:
    # Fallback: attempt relative import if package has been fully moved
    try:
        from .logstash_parser import LogstashParser, parse_config_to_tree  # type: ignore
    except Exception as e:
        raise ImportError(f"Could not import LogstashParser: {e}")

__all__ = ["LogstashParser", "parse_config_to_tree"]
