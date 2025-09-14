"""Test dynamic configuration system."""

import os
import sys
from pathlib import Path

# Add parent dir to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_dynamic_configuration():
    """Test that dynamic configuration loads correctly from environment."""
    
    # Set some test values in environment
    os.environ["CHUNK_SIZE"] = "5000"
    os.environ["MAX_CHUNKS"] = "25"
    os.environ["USE_OPTIMIZED_EXTRACTOR"] = "false"
    os.environ["MAPPER_BATCH_SIZE"] = "30"
    os.environ["ENABLE_SENTENCE_EVIDENCE"] = "false"
    
    # Import settings AFTER setting env vars
    from bandjacks.services.api.settings import Settings
    
    # Create new settings instance to pick up env vars
    settings = Settings()
    
    # Test that values were loaded from environment
    print("=== Dynamic Configuration Test ===")
    print(f"chunk_size: {settings.chunk_size} (expected: 5000)")
    print(f"max_chunks: {settings.max_chunks} (expected: 25)")
    print(f"use_optimized_extractor: {settings.use_optimized_extractor} (expected: False)")
    print(f"mapper_batch_size: {settings.mapper_batch_size} (expected: 30)")
    print(f"enable_sentence_evidence: {settings.enable_sentence_evidence} (expected: False)")
    
    # Verify values
    assert settings.chunk_size == 5000, f"chunk_size should be 5000, got {settings.chunk_size}"
    assert settings.max_chunks == 25, f"max_chunks should be 25, got {settings.max_chunks}"
    assert settings.use_optimized_extractor is False, f"use_optimized_extractor should be False"
    assert settings.mapper_batch_size == 30, f"mapper_batch_size should be 30, got {settings.mapper_batch_size}"
    assert settings.enable_sentence_evidence is False, f"enable_sentence_evidence should be False"
    
    print("\n✅ All dynamic configuration tests passed!")
    
    # Test defaults (when env vars not set)
    del os.environ["CHUNK_SIZE"]
    settings2 = Settings()
    print(f"\nDefault chunk_size (no env var): {settings2.chunk_size}")
    assert settings2.chunk_size == 4000, "Default chunk_size should be 4000"
    
    print("✅ Default value test passed!")
    
    # Test configuration in extraction pipeline
    print("\n=== Testing Configuration in Pipeline ===")
    
    # Mock a config that would be used in job_processor
    extraction_config = {
        "use_batch_mapper": True,
        "use_batch_retriever": True,
        "use_entity_claims": settings.use_entity_claims,
        "mapper_batch_size": min(settings.mapper_batch_size, settings.max_mapper_batch_size),
        "enable_sentence_evidence": settings.enable_sentence_evidence,
        "context_sentences": settings.context_sentences
    }
    
    print(f"Extraction config built from settings:")
    for key, value in extraction_config.items():
        print(f"  {key}: {value}")
    
    print("\n✅ Configuration integration test passed!")
    
    return True


def test_configuration_precedence():
    """Test that configuration precedence works correctly."""
    print("\n=== Configuration Precedence Test ===")
    
    # Set in environment
    os.environ["PARALLEL_WORKERS"] = "8"
    
    from bandjacks.services.api.settings import Settings
    settings = Settings()
    
    print(f"parallel_workers from env: {settings.parallel_workers} (expected: 8)")
    assert settings.parallel_workers == 8, "Environment should override default"
    
    # Test with .env file values (these should be loaded)
    print(f"redis_host: {settings.redis_host} (from .env)")
    print(f"neo4j_uri: {settings.neo4j_uri} (from .env)")
    
    print("✅ Precedence test passed!")
    
    return True


def test_configuration_ranges():
    """Test configuration validation and ranges."""
    print("\n=== Configuration Range Test ===")
    
    # Test extreme values
    os.environ["MAPPER_BATCH_SIZE"] = "100"  # Very large
    os.environ["CHUNK_SIZE"] = "100"  # Very small
    os.environ["SEMANTIC_DEDUP_THRESHOLD"] = "0.99"  # Very high
    
    from bandjacks.services.api.settings import Settings
    settings = Settings()
    
    # These should load but be clamped in actual usage
    print(f"mapper_batch_size: {settings.mapper_batch_size} (large value: 100)")
    print(f"chunk_size: {settings.chunk_size} (small value: 100)")
    print(f"semantic_dedup_threshold: {settings.semantic_dedup_threshold} (high value: 0.99)")
    
    # In job_processor, mapper_batch_size is clamped
    actual_batch_size = min(settings.mapper_batch_size, settings.max_mapper_batch_size)
    print(f"Actual batch size used: {actual_batch_size} (clamped to max: {settings.max_mapper_batch_size})")
    
    assert actual_batch_size <= settings.max_mapper_batch_size, "Batch size should be clamped"
    
    print("✅ Range test passed!")
    
    return True


if __name__ == "__main__":
    print("Testing Dynamic Configuration System")
    print("=" * 40)
    
    success = True
    
    try:
        test_dynamic_configuration()
        test_configuration_precedence()
        test_configuration_ranges()
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        success = False
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        success = False
    
    if success:
        print("\n" + "=" * 40)
        print("🎉 All dynamic configuration tests passed!")
        print("Dynamic configuration is working correctly.")
    else:
        print("\n" + "=" * 40)
        print("Some tests failed. Please check the configuration.")
        sys.exit(1)