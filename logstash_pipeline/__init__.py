"""Package wrapper for Logstash Pipeline modules.

This package provides a stable import path while leaving the
existing top-level modules untouched for backward compatibility.
"""
from .parser import LogstashParser, parse_config_to_tree

__all__ = ["LogstashParser", "parse_config_to_tree"]
