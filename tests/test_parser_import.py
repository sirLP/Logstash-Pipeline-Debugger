def test_imports():
    # Ensure the package import path works
    try:
        from logstash_pipeline import LogstashParser, parse_config_to_tree
    except Exception as e:
        raise AssertionError(f"Package import failed: {e}")

    # Ensure legacy import still works
    try:
        import logstash_parser as legacy
        assert hasattr(legacy, 'LogstashParser')
        assert hasattr(legacy, 'parse_config_to_tree')
    except Exception as e:
        raise AssertionError(f"Legacy import failed: {e}")
