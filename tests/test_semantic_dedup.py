"""Tests for semantic deduplication module."""

import pytest
from unittest.mock import patch, MagicMock
import numpy as np
from bandjacks.llm.semantic_dedup import SemanticDeduplicator


class TestSemanticDeduplicator:
    """Test suite for semantic deduplication functionality."""
    
    @pytest.fixture
    def deduplicator(self):
        """Create a deduplicator instance."""
        return SemanticDeduplicator(similarity_threshold=0.85, entity_threshold=0.90)
    
    def test_cosine_similarity(self, deduplicator):
        """Test cosine similarity calculation."""
        # Identical vectors
        vec1 = np.array([1, 0, 0])
        vec2 = np.array([1, 0, 0])
        assert deduplicator.cosine_similarity(vec1, vec2) == pytest.approx(1.0)
        
        # Orthogonal vectors
        vec1 = np.array([1, 0, 0])
        vec2 = np.array([0, 1, 0])
        assert deduplicator.cosine_similarity(vec1, vec2) == pytest.approx(0.0)
        
        # Similar vectors
        vec1 = np.array([1, 1, 0])
        vec2 = np.array([1, 1, 0.1])
        similarity = deduplicator.cosine_similarity(vec1, vec2)
        assert 0.98 < similarity < 1.0
        
        # Zero vectors
        vec1 = np.array([0, 0, 0])
        vec2 = np.array([1, 1, 1])
        assert deduplicator.cosine_similarity(vec1, vec2) == 0.0
    
    @patch('bandjacks.llm.semantic_dedup.batch_encode')
    def test_deduplicate_evidence(self, mock_encode, deduplicator):
        """Test evidence deduplication with mocked embeddings."""
        # Setup mock embeddings
        evidence_list = [
            "APT29 uses spearphishing emails with malicious attachments",
            "APT29 employs spearphishing messages containing harmful attachments",  # Similar
            "The group exfiltrates data using encrypted channels",
            "Data is exfiltrated through encrypted communication channels",  # Similar
            "They establish persistence through registry modifications"
        ]
        
        # Create mock embeddings - similar sentences have high cosine similarity
        mock_embeddings = [
            [1.0, 0.0, 0.0],  # Evidence 0
            [0.99, 0.1, 0.0],  # Evidence 1 (similar to 0)
            [0.0, 1.0, 0.0],  # Evidence 2
            [0.1, 0.99, 0.0],  # Evidence 3 (similar to 2)
            [0.0, 0.0, 1.0],  # Evidence 4 (unique)
        ]
        mock_encode.return_value = mock_embeddings
        
        # Deduplicate
        result = deduplicator.deduplicate_evidence(evidence_list)
        
        # Should keep one from each similar pair plus the unique one
        assert len(result) == 3
        # Should keep longer evidence from similar pairs
        assert evidence_list[1] in result  # Longer than evidence[0]
        assert evidence_list[3] in result  # Longer than evidence[2]
        assert evidence_list[4] in result  # Unique
    
    @patch('bandjacks.llm.semantic_dedup.batch_encode')
    @patch.object(SemanticDeduplicator, 'deduplicate_evidence')
    def test_deduplicate_entities(self, mock_dedup_evidence, mock_encode, deduplicator):
        """Test entity deduplication and alias tracking."""
        entities = {
            "apt29": {
                "name": "APT29",
                "type": "threat-actor",
                "confidence": 85,
                "evidence": ["APT29 is a sophisticated threat actor"],
                "line_refs": [10, 20]
            },
            "cozy_bear": {
                "name": "Cozy Bear",
                "type": "threat-actor", 
                "confidence": 80,
                "evidence": ["Cozy Bear targets government entities"],
                "line_refs": [30, 40]
            },
            "nobelium": {
                "name": "NOBELIUM",
                "type": "threat-actor",
                "confidence": 90,
                "evidence": ["NOBELIUM conducted the SolarWinds attack"],
                "line_refs": [50]
            },
            "lazarus": {
                "name": "Lazarus Group",
                "type": "threat-actor",
                "confidence": 75,
                "evidence": ["Lazarus Group targets financial institutions"],
                "line_refs": [60, 70]
            }
        }
        
        # Mock embeddings - APT29, Cozy Bear, and NOBELIUM are similar
        mock_embeddings = [
            [1.0, 0.0, 0.0],   # APT29
            [0.95, 0.05, 0.0], # Cozy Bear (similar to APT29)
            [0.93, 0.07, 0.0], # NOBELIUM (similar to APT29)
            [0.0, 1.0, 0.0],   # Lazarus (different)
        ]
        mock_encode.return_value = mock_embeddings
        
        # Mock deduplicate_evidence to return combined evidence
        mock_dedup_evidence.return_value = [
            "APT29 is a sophisticated threat actor",
            "Cozy Bear targets government entities",
            "NOBELIUM conducted the SolarWinds attack"
        ]
        
        # Deduplicate
        result = deduplicator.deduplicate_entities(entities)
        
        # Should merge APT29, Cozy Bear, and NOBELIUM
        assert len(result) == 2  # APT29 cluster and Lazarus
        
        # Check if aliases were tracked
        apt29_cluster = result.get("apt29")
        if apt29_cluster:
            assert apt29_cluster["name"] == "APT29"  # First entity's name
            assert "aliases" in apt29_cluster
            assert set(apt29_cluster["aliases"]) == {"Cozy Bear", "NOBELIUM"}
            assert apt29_cluster["confidence"] == 90  # Highest confidence
            # Should have combined evidence
            assert len(apt29_cluster["evidence"]) >= 1
        
        # Lazarus should remain separate
        assert "lazarus" in result
        assert result["lazarus"]["name"] == "Lazarus Group"
    
    @patch('bandjacks.llm.semantic_dedup.batch_encode')
    @patch.object(SemanticDeduplicator, 'deduplicate_evidence', return_value=["Injects code into processes", "Performs process injection"])
    def test_deduplicate_techniques(self, mock_dedup_evidence, mock_encode, deduplicator):
        """Test technique deduplication preserving parent/subtechnique relationships."""
        techniques = {
            "T1055": {
                "name": "Process Injection",
                "confidence": 80,
                "evidence": ["Injects code into processes"],
                "line_refs": [10]
            },
            "T1055.001": {
                "name": "Dynamic-link Library Injection", 
                "confidence": 85,
                "evidence": ["Uses DLL injection technique"],
                "line_refs": [20]
            },
            "T1055_duplicate": {
                "name": "Process Injection",
                "confidence": 75,
                "evidence": ["Performs process injection"],
                "line_refs": [30]
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "confidence": 70,
                "evidence": ["Executes commands via interpreter"],
                "line_refs": [40]
            }
        }
        
        # Mock embeddings
        mock_embeddings = [
            [1.0, 0.0, 0.0],   # T1055
            [0.8, 0.2, 0.0],   # T1055.001 (somewhat similar but subtechnique)
            [0.95, 0.05, 0.0], # T1055_duplicate (very similar to T1055)
            [0.0, 1.0, 0.0],   # T1059 (different)
        ]
        mock_encode.return_value = mock_embeddings
        
        # Deduplicate
        result = deduplicator.deduplicate_techniques(techniques)
        
        # Should merge T1055 and T1055_duplicate but not T1055.001
        assert len(result) == 3  # T1055 (merged), T1055.001, T1059
        
        # Check T1055 was merged with duplicate
        t1055 = result.get("T1055")
        if t1055:
            assert t1055["confidence"] == 80  # Max confidence
            assert "merged_from" in t1055
            assert "T1055_duplicate" in t1055["merged_from"]
        
        # T1055.001 should remain separate (parent/subtechnique preservation)
        assert "T1055.001" in result
        
        # T1059 should remain separate
        assert "T1059" in result
    
    def test_deduplicate_evidence_empty(self, deduplicator):
        """Test handling of empty evidence list."""
        assert deduplicator.deduplicate_evidence([]) == []
        assert deduplicator.deduplicate_evidence(["single"]) == ["single"]
    
    def test_deduplicate_entities_empty(self, deduplicator):
        """Test handling of empty entities dict."""
        assert deduplicator.deduplicate_entities({}) == {}
        single = {"e1": {"name": "Entity1"}}
        assert deduplicator.deduplicate_entities(single) == single
    
    def test_deduplicate_techniques_empty(self, deduplicator):
        """Test handling of empty techniques dict."""
        assert deduplicator.deduplicate_techniques({}) == {}
        single = {"T1055": {"name": "Process Injection"}}
        assert deduplicator.deduplicate_techniques(single) == single
    
    @patch('bandjacks.llm.semantic_dedup.batch_encode')
    def test_deduplicate_evidence_with_none_embeddings(self, mock_encode, deduplicator):
        """Test handling of None embeddings from batch_encode."""
        evidence_list = ["evidence1", "evidence2", "evidence3"]
        
        # Some embeddings are None (encoding failed)
        mock_embeddings = [
            [1.0, 0.0, 0.0],  # Evidence 0
            None,             # Evidence 1 (failed)
            [0.0, 1.0, 0.0],  # Evidence 2
        ]
        mock_encode.return_value = mock_embeddings
        
        # Should handle None gracefully
        result = deduplicator.deduplicate_evidence(evidence_list)
        assert len(result) == 2  # Only non-None embeddings
        assert "evidence1" in result
        assert "evidence3" in result
    
    @patch('bandjacks.llm.semantic_dedup.batch_encode')
    def test_merge_similar_entities_preserves_data(self, mock_encode, deduplicator):
        """Test that entity merging preserves all important data."""
        entities = {
            "apt29": {
                "name": "APT29",
                "type": "threat-actor",
                "confidence": 85,
                "evidence": ["Evidence 1", "Evidence 2"],
                "line_refs": [10, 20],
                "aliases": ["Dukes"]
            },
            "cozy_bear": {
                "name": "Cozy Bear",
                "type": "threat-actor",
                "confidence": 90,
                "evidence": ["Evidence 3", "Evidence 2"],  # Duplicate evidence
                "line_refs": [30, 20],  # Some overlap
            }
        }
        
        # Mock embeddings - entities are similar
        mock_embeddings = [
            [1.0, 0.0],
            [0.95, 0.05],
        ]
        mock_encode.return_value = mock_embeddings
        
        # Mock evidence deduplication to return unique evidence
        with patch.object(deduplicator, 'deduplicate_evidence', return_value=["Evidence 1", "Evidence 3", "Evidence 2"]):
            result = deduplicator.deduplicate_entities(entities)
        
        # Check merged entity
        assert len(result) == 1
        merged = list(result.values())[0]
        
        # Should have highest confidence
        assert merged["confidence"] == 90
        
        # Should preserve and combine aliases
        assert "Cozy Bear" in merged.get("aliases", [])
        assert "Dukes" in merged.get("aliases", []) or merged["name"] == "APT29"
        
        # Should combine line refs
        assert set(merged["line_refs"]) == {10, 20, 30}
        
        # Should track what was merged
        assert "merged_from" in merged


class TestConsolidatorBaseIntegration:
    """Test ConsolidatorBase integration with semantic deduplication."""
    
    @patch('bandjacks.services.api.settings.settings')
    def test_consolidator_base_with_semantic_enabled(self, mock_settings):
        """Test ConsolidatorBase when semantic dedup is enabled."""
        from bandjacks.llm.consolidator_base import ConsolidatorBase
        
        # Mock settings
        mock_settings.enable_semantic_dedup = True
        mock_settings.semantic_dedup_threshold = 0.85
        mock_settings.entity_dedup_threshold = 0.90
        
        # Create consolidator
        consolidator = ConsolidatorBase()
        
        # Should have semantic dedup enabled
        assert consolidator.use_semantic_dedup is True
        assert hasattr(consolidator, 'semantic_dedup')
        assert consolidator.semantic_dedup is not None
    
    @patch('bandjacks.services.api.settings.settings')
    def test_consolidator_base_with_semantic_disabled(self, mock_settings):
        """Test ConsolidatorBase when semantic dedup is disabled."""
        from bandjacks.llm.consolidator_base import ConsolidatorBase
        
        # Mock settings
        mock_settings.enable_semantic_dedup = False
        
        # Create consolidator
        consolidator = ConsolidatorBase()
        
        # Should fall back to Jaccard
        assert consolidator.use_semantic_dedup is False
        assert not hasattr(consolidator, 'semantic_dedup')
    
    def test_consolidator_base_jaccard_dedup(self):
        """Test Jaccard-based deduplication fallback."""
        from bandjacks.llm.consolidator_base import ConsolidatorBase
        
        consolidator = ConsolidatorBase()
        
        evidence_list = [
            "APT29 uses spearphishing emails with malicious attachments",
            "APT29 uses spearphishing emails with malicious attachments",  # Exact duplicate
            "The group exfiltrates data using encrypted channels",
            "The group exfiltrates data through encrypted communication channels",  # <85% similar
            "Different evidence about persistence"
        ]
        
        # Use Jaccard dedup directly
        result = consolidator._jaccard_dedup(evidence_list)
        
        # Should only merge the exact duplicate (Jaccard similarity < 0.85 for the exfiltration sentences)
        assert len(result) == 4
        # Check that unique evidence is preserved
        assert "APT29 uses spearphishing emails with malicious attachments" in result
        assert "Different evidence about persistence" in result
        # Both exfiltration sentences should be in result (not similar enough by Jaccard)
        assert "The group exfiltrates data using encrypted channels" in result
        assert "The group exfiltrates data through encrypted communication channels" in result