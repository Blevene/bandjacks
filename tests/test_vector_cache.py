"""Tests for vector search caching functionality."""

import time
import pytest
from unittest.mock import Mock, patch, MagicMock

from bandjacks.llm.vector_cache import VectorSearchCache, get_vector_cache
from bandjacks.llm.batch_retriever import BatchRetrieverAgent
from bandjacks.llm.memory import WorkingMemory


class TestVectorSearchCache:
    """Test the VectorSearchCache class."""
    
    def test_cache_init_without_redis(self):
        """Test cache initialization when Redis is not available."""
        cache = VectorSearchCache(
            max_size=100,
            ttl=60,
            redis_enabled=False
        )
        
        assert cache.max_size == 100
        assert cache.ttl == 60
        assert cache.redis_enabled is False
        assert cache.redis_client is None
        assert len(cache.l1_cache) == 0
    
    def test_l1_cache_embedding(self):
        """Test L1 cache for embeddings."""
        cache = VectorSearchCache(max_size=10, ttl=60, redis_enabled=False)
        
        # Test cache miss
        embedding = cache.get_embedding("test text")
        assert embedding is None
        assert cache.l1_misses == 1
        assert cache.l1_hits == 0
        
        # Add to cache
        test_vector = [0.1, 0.2, 0.3]
        cache.set_embedding("test text", test_vector)
        
        # Test cache hit
        cached_embedding = cache.get_embedding("test text")
        assert cached_embedding == test_vector
        assert cache.l1_hits == 1
        assert cache.l1_misses == 1
    
    def test_l1_cache_candidates(self):
        """Test L1 cache for search results."""
        cache = VectorSearchCache(max_size=10, ttl=60, redis_enabled=False)
        
        # Test cache miss
        candidates = cache.get_candidates("test text", top_k=10)
        assert candidates is None
        
        # Add to cache
        test_candidates = [
            {"external_id": "T1055", "name": "Process Injection", "score": 0.95},
            {"external_id": "T1057", "name": "Process Discovery", "score": 0.88}
        ]
        cache.set_candidates("test text", 10, test_candidates)
        
        # Test cache hit
        cached_candidates = cache.get_candidates("test text", 10)
        assert cached_candidates == test_candidates
        assert cache.l1_hits == 1
        
        # Different top_k should miss
        different_k = cache.get_candidates("test text", 5)
        assert different_k is None
    
    def test_l1_cache_lru_eviction(self):
        """Test LRU eviction policy in L1 cache."""
        cache = VectorSearchCache(max_size=3, ttl=3600, redis_enabled=False)
        
        # Fill cache to capacity
        cache.set_embedding("text1", [0.1])
        cache.set_embedding("text2", [0.2])
        cache.set_embedding("text3", [0.3])
        
        assert len(cache.l1_cache) == 3
        
        # Add one more - should evict text1 (least recently used)
        cache.set_embedding("text4", [0.4])
        assert len(cache.l1_cache) == 3
        
        # text1 should be evicted
        assert cache.get_embedding("text1") is None
        # Others should still be there
        assert cache.get_embedding("text2") == [0.2]
        assert cache.get_embedding("text3") == [0.3]
        assert cache.get_embedding("text4") == [0.4]
    
    def test_cache_ttl_expiration(self):
        """Test TTL expiration of cache entries."""
        cache = VectorSearchCache(max_size=10, ttl=1, redis_enabled=False)  # 1 second TTL
        
        # Add to cache
        cache.set_embedding("test text", [0.1, 0.2])
        
        # Should be in cache immediately
        assert cache.get_embedding("test text") == [0.1, 0.2]
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Should be expired
        assert cache.get_embedding("test text") is None
    
    def test_cache_stats(self):
        """Test cache statistics tracking."""
        cache = VectorSearchCache(max_size=10, ttl=60, redis_enabled=False)
        
        # Generate some cache activity
        cache.get_embedding("miss1")  # miss
        cache.set_embedding("hit1", [0.1])
        cache.get_embedding("hit1")  # hit
        cache.get_embedding("miss2")  # miss
        
        stats = cache.get_stats()
        
        assert stats["l1_hits"] == 1
        assert stats["l1_misses"] == 2
        assert stats["l1_size"] == 1
        assert abs(stats["l1_hit_rate"] - 1/3) < 0.01
        # Overall hit rate includes both L1 and L2, but L2 has 1 additional miss during setup
        assert abs(stats["overall_hit_rate"] - 1/5) < 0.01
    
    def test_cache_clear(self):
        """Test clearing the cache."""
        cache = VectorSearchCache(max_size=10, ttl=60, redis_enabled=False)
        
        # Add some entries
        cache.set_embedding("text1", [0.1])
        cache.set_embedding("text2", [0.2])
        cache.set_candidates("text1", 10, [{"id": "T1055"}])
        
        assert len(cache.l1_cache) == 3
        
        # Clear cache
        cache.clear()
        
        assert len(cache.l1_cache) == 0
        assert cache.l1_hits == 0
        assert cache.l1_misses == 0
    
    @patch('bandjacks.llm.vector_cache.redis.Redis')
    def test_redis_integration(self, mock_redis_class):
        """Test Redis integration for L2 cache."""
        # Mock Redis client
        mock_redis = MagicMock()
        mock_redis_class.return_value = mock_redis
        mock_redis.ping.return_value = True
        
        cache = VectorSearchCache(
            max_size=10,
            ttl=60,
            redis_enabled=True,
            redis_host="localhost",
            redis_port=6379
        )
        
        assert cache.redis_enabled is True
        assert cache.redis_client is not None
        
        # Test L2 cache miss then hit
        mock_redis.get.return_value = None
        result = cache.get_embedding("test")
        assert result is None
        assert cache.l2_misses == 1
        
        # Simulate L2 hit
        import pickle
        test_vector = [0.1, 0.2]
        mock_redis.get.return_value = pickle.dumps(test_vector)
        result = cache.get_embedding("test2")
        assert result == test_vector
        assert cache.l2_hits == 1
    
    def test_get_vector_cache_singleton(self):
        """Test that get_vector_cache returns a singleton."""
        cache1 = get_vector_cache()
        cache2 = get_vector_cache()
        
        assert cache1 is cache2


class TestBatchRetrieverWithCache:
    """Test BatchRetrieverAgent with caching enabled."""
    
    @patch('bandjacks.llm.batch_retriever.batch_encode')
    @patch('bandjacks.llm.batch_retriever.get_opensearch_client')
    @patch('bandjacks.llm.batch_retriever.get_vector_cache')
    def test_batch_retriever_with_result_cache(self, mock_get_cache, mock_get_client, mock_encode):
        """Test that BatchRetrieverAgent uses result cache correctly."""
        # Setup mocks
        mock_cache = Mock(spec=VectorSearchCache)
        mock_get_cache.return_value = mock_cache
        
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        # Create test data
        mem = WorkingMemory()
        mem.spans = [
            {"text": "test span 1"},
            {"text": "test span 2"},
            {"text": "test span 1"},  # Duplicate
        ]
        
        config = {
            "top_k": 5,
            "use_vector_cache": True
        }
        
        # Mock cache responses
        cached_result = [
            {"external_id": "T1055", "name": "Process Injection", "score": 0.95}
        ]
        
        # First call returns None (cache miss), second returns cached
        mock_cache.get_candidates.side_effect = [None, None, cached_result]
        mock_cache.get_embedding.return_value = None
        
        # Mock encoding
        mock_encode.return_value = [[0.1, 0.2], [0.3, 0.4]]
        
        # Mock OpenSearch response
        mock_client.msearch.return_value = {
            "responses": [
                {
                    "hits": {
                        "hits": [
                            {
                                "_source": {
                                    "external_id": "T1057",
                                    "name": "Process Discovery",
                                    "kb_type": "AttackPattern"
                                },
                                "_score": 0.88
                            }
                        ]
                    }
                },
                {
                    "hits": {
                        "hits": [
                            {
                                "_source": {
                                    "external_id": "T1059",
                                    "name": "Command and Scripting Interpreter",
                                    "kb_type": "AttackPattern"
                                },
                                "_score": 0.92
                            }
                        ]
                    }
                }
            ]
        }
        
        # Mock settings
        with patch('bandjacks.services.api.settings.settings') as mock_settings:
            mock_settings.vector_cache_enabled = True
            mock_settings.vector_result_cache_enabled = True
            mock_settings.os_index_nodes = "test_index"
            
            # Run the agent
            agent = BatchRetrieverAgent()
            agent.run(mem, config)
        
        # Verify cache was checked for candidates
        assert mock_cache.get_candidates.call_count >= 2
        
        # Verify new results were cached
        assert mock_cache.set_candidates.call_count >= 1
        
        # Verify candidates were assigned to spans
        assert len(mem.candidates) > 0
    
    @patch('bandjacks.llm.batch_retriever.batch_encode')
    @patch('bandjacks.llm.batch_retriever.get_opensearch_client')  
    @patch('bandjacks.llm.batch_retriever.get_vector_cache')
    def test_batch_retriever_cache_hit_early_return(self, mock_get_cache, mock_get_client, mock_encode):
        """Test that BatchRetrieverAgent returns early on full cache hit."""
        # Setup mocks
        mock_cache = Mock(spec=VectorSearchCache)
        mock_get_cache.return_value = mock_cache
        
        # Create test data
        mem = WorkingMemory()
        mem.spans = [
            {"text": "cached span"}
        ]
        
        config = {
            "top_k": 5,
            "use_vector_cache": True
        }
        
        # Mock full cache hit
        cached_result = [
            {"external_id": "T1055", "name": "Process Injection", "score": 0.95}
        ]
        mock_cache.get_candidates.return_value = cached_result
        mock_cache.get_stats.return_value = {
            "overall_hit_rate": 1.0,
            "l1_hits": 1,
            "l1_misses": 0,
            "l2_hits": 0,
            "l2_misses": 0
        }
        
        # Mock settings
        with patch('bandjacks.services.api.settings.settings') as mock_settings:
            mock_settings.vector_cache_enabled = True
            mock_settings.vector_result_cache_enabled = True
            
            # Run the agent
            agent = BatchRetrieverAgent()
            agent.run(mem, config)
        
        # Verify early return - no encoding or OpenSearch calls
        mock_encode.assert_not_called()
        mock_get_client.assert_not_called()
        
        # Verify candidates were assigned from cache
        assert 0 in mem.candidates
        assert mem.candidates[0] == cached_result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])