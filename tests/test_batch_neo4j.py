"""Tests for batch Neo4j query optimization."""

import pytest
from unittest.mock import Mock, patch, MagicMock, call
import json

from bandjacks.llm.batch_neo4j import BatchNeo4jHelper


class TestBatchNeo4jHelper:
    """Test the BatchNeo4jHelper class."""
    
    def test_batch_get_technique_tactics(self):
        """Test batch fetching of technique tactics."""
        # Mock driver
        mock_driver = Mock()
        mock_session = Mock()
        mock_driver.session.return_value.__enter__ = Mock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = Mock(return_value=None)
        
        # Mock query results
        mock_result = [
            {"tech_id": "attack-pattern--1", "tactics": ["initial-access", "execution"]},
            {"tech_id": "attack-pattern--2", "tactics": ["persistence"]},
        ]
        mock_session.run.return_value = mock_result
        
        # Create helper and test
        helper = BatchNeo4jHelper(mock_driver)
        
        technique_ids = ["attack-pattern--1", "attack-pattern--2", "attack-pattern--3"]
        results = helper.batch_get_technique_tactics(technique_ids)
        
        # Verify results
        assert results["attack-pattern--1"] == ["initial-access", "execution"]
        assert results["attack-pattern--2"] == ["persistence"]
        assert results["attack-pattern--3"] == []  # Not found
        
        # Verify query was called once with all IDs
        mock_session.run.assert_called_once()
        call_args = mock_session.run.call_args
        assert call_args[1]["technique_ids"] == technique_ids
    
    def test_batch_get_technique_tactics_with_cache(self):
        """Test that cached tactics are not re-queried."""
        # Mock driver
        mock_driver = Mock()
        mock_session = Mock()
        mock_driver.session.return_value.__enter__ = Mock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = Mock(return_value=None)
        
        # Mock query results for first call
        mock_result = [
            {"tech_id": "attack-pattern--1", "tactics": ["initial-access"]},
        ]
        mock_session.run.return_value = mock_result
        
        # Create helper and make first call
        helper = BatchNeo4jHelper(mock_driver)
        results1 = helper.batch_get_technique_tactics(["attack-pattern--1"])
        assert results1["attack-pattern--1"] == ["initial-access"]
        
        # Reset mock and make second call with same ID plus new ones
        mock_session.reset_mock()
        mock_result2 = [
            {"tech_id": "attack-pattern--2", "tactics": ["persistence"]},
        ]
        mock_session.run.return_value = mock_result2
        
        results2 = helper.batch_get_technique_tactics(["attack-pattern--1", "attack-pattern--2"])
        
        # Verify cached result is used
        assert results2["attack-pattern--1"] == ["initial-access"]  # From cache
        assert results2["attack-pattern--2"] == ["persistence"]  # From query
        
        # Verify only uncached IDs were queried
        mock_session.run.assert_called_once()
        call_args = mock_session.run.call_args
        assert call_args[1]["technique_ids"] == ["attack-pattern--2"]
    
    def test_batch_check_adjacencies(self):
        """Test batch checking of technique adjacencies."""
        # Mock driver
        mock_driver = Mock()
        mock_session = Mock()
        mock_driver.session.return_value.__enter__ = Mock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = Mock(return_value=None)
        
        # Mock query results
        mock_result = [
            {"source": "attack-pattern--1", "target": "attack-pattern--2", "adjacency_count": 5},
            {"source": "attack-pattern--2", "target": "attack-pattern--3", "adjacency_count": 0},
        ]
        mock_session.run.return_value = mock_result
        
        # Create helper and test
        helper = BatchNeo4jHelper(mock_driver)
        
        pairs = [
            ("attack-pattern--1", "attack-pattern--2"),
            ("attack-pattern--2", "attack-pattern--3"),
            ("attack-pattern--3", "attack-pattern--4"),  # Not in results
        ]
        results = helper.batch_check_adjacencies(pairs)
        
        # Verify results
        assert results[("attack-pattern--1", "attack-pattern--2")] == 5
        assert results[("attack-pattern--2", "attack-pattern--3")] == 0
        assert results[("attack-pattern--3", "attack-pattern--4")] == 0  # Default
    
    def test_batch_create_attack_actions(self):
        """Test batch creation of attack actions."""
        # Mock driver
        mock_driver = Mock()
        mock_session = Mock()
        mock_driver.session.return_value.__enter__ = Mock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = Mock(return_value=None)
        
        # Create helper and test
        helper = BatchNeo4jHelper(mock_driver)
        
        actions = [
            {
                "action_id": "action--1",
                "attack_pattern_ref": "attack-pattern--1",
                "confidence": 80.0,
                "order": 1,
                "description": "Test action 1",
                "evidence": [{"text": "evidence1"}],
                "reason": "test reason"
            },
            {
                "action_id": "action--2",
                "technique_id": "attack-pattern--2",
                "confidence": 75.0,
                "order": 2,
                "description": "Test action 2"
            }
        ]
        
        result = helper.batch_create_attack_actions("episode--123", actions)
        
        # Verify success
        assert result is True
        
        # Verify query was called
        mock_session.run.assert_called_once()
        call_args = mock_session.run.call_args
        assert call_args[1]["episode_id"] == "episode--123"
        assert len(call_args[1]["actions"]) == 2
        
        # Check action data formatting
        action_data = call_args[1]["actions"]
        assert action_data[0]["action_id"] == "action--1"
        assert action_data[0]["attack_pattern_ref"] == "attack-pattern--1"
        assert action_data[0]["confidence"] == 80.0
        assert json.loads(action_data[0]["evidence"]) == [{"text": "evidence1"}]
        
        assert action_data[1]["action_id"] == "action--2"
        assert action_data[1]["attack_pattern_ref"] == "attack-pattern--2"
        assert action_data[1]["evidence"] == "[]"
    
    def test_batch_create_next_edges(self):
        """Test batch creation of NEXT edges."""
        # Mock driver
        mock_driver = Mock()
        mock_session = Mock()
        mock_driver.session.return_value.__enter__ = Mock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = Mock(return_value=None)
        
        # Create helper and test
        helper = BatchNeo4jHelper(mock_driver)
        
        edges = [
            {
                "source": "action--1",
                "target": "action--2",
                "probability": 0.8,
                "rationale": "sequential"
            },
            {
                "source": "action--2",
                "target": "action--3",
                "probability": 0.6,
                "rationale": "tactic progression"
            }
        ]
        
        result = helper.batch_create_next_edges(edges)
        
        # Verify success
        assert result is True
        
        # Verify query was called
        mock_session.run.assert_called_once()
        call_args = mock_session.run.call_args
        assert len(call_args[1]["edges"]) == 2
        
        # Check edge data
        edge_data = call_args[1]["edges"]
        assert edge_data[0]["source"] == "action--1"
        assert edge_data[0]["target"] == "action--2"
        assert edge_data[0]["probability"] == 0.8
        assert edge_data[0]["rationale"] == "sequential"
    
    def test_batch_get_tactic_alignments(self):
        """Test batch fetching of tactic alignments."""
        # Mock driver
        mock_driver = Mock()
        mock_session = Mock()
        mock_driver.session.return_value.__enter__ = Mock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = Mock(return_value=None)
        
        # Mock query results
        mock_result = [
            {
                "source": "attack-pattern--1",
                "target": "attack-pattern--2",
                "tactics1": ["initial-access", "execution"],
                "tactics2": ["execution", "persistence"],
                "same_tactic": True
            },
            {
                "source": "attack-pattern--2",
                "target": "attack-pattern--3",
                "tactics1": ["persistence"],
                "tactics2": ["defense-evasion"],
                "same_tactic": False
            }
        ]
        mock_session.run.return_value = mock_result
        
        # Create helper and test
        helper = BatchNeo4jHelper(mock_driver)
        
        pairs = [
            ("attack-pattern--1", "attack-pattern--2"),
            ("attack-pattern--2", "attack-pattern--3")
        ]
        results = helper.batch_get_tactic_alignments(pairs)
        
        # Verify results
        pair1 = ("attack-pattern--1", "attack-pattern--2")
        assert results[pair1]["source_tactics"] == ["initial-access", "execution"]
        assert results[pair1]["target_tactics"] == ["execution", "persistence"]
        assert results[pair1]["same_tactic"] is True
        
        pair2 = ("attack-pattern--2", "attack-pattern--3")
        assert results[pair2]["same_tactic"] is False
    
    def test_get_tactic_order(self):
        """Test tactic order mapping."""
        mock_driver = Mock()
        helper = BatchNeo4jHelper(mock_driver)
        
        # Test known tactics
        assert helper.get_tactic_order("reconnaissance") == 1
        assert helper.get_tactic_order("initial-access") == 3
        assert helper.get_tactic_order("execution") == 4
        assert helper.get_tactic_order("persistence") == 5
        assert helper.get_tactic_order("defense-evasion") == 7
        assert helper.get_tactic_order("exfiltration") == 13
        assert helper.get_tactic_order("impact") == 14
        
        # Test unknown tactic
        assert helper.get_tactic_order("unknown-tactic") == 7  # Default
    
    def test_clear_cache(self):
        """Test cache clearing."""
        # Mock driver
        mock_driver = Mock()
        mock_session = Mock()
        mock_driver.session.return_value.__enter__ = Mock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = Mock(return_value=None)
        
        # Create helper and populate cache
        helper = BatchNeo4jHelper(mock_driver)
        helper._technique_cache["test1"] = {"data": "test"}
        helper._tactic_cache["test2"] = ["tactic1"]
        
        # Clear cache
        helper.clear_cache()
        
        # Verify caches are empty
        assert len(helper._technique_cache) == 0
        assert len(helper._tactic_cache) == 0
    
    def test_empty_inputs(self):
        """Test that empty inputs are handled gracefully."""
        mock_driver = Mock()
        helper = BatchNeo4jHelper(mock_driver)
        
        # Test empty lists
        assert helper.batch_get_technique_tactics([]) == {}
        assert helper.batch_get_technique_metadata([]) == {}
        assert helper.batch_check_adjacencies([]) == {}
        assert helper.batch_get_tactic_alignments([]) == {}
        assert helper.batch_create_attack_actions("episode--123", []) is True
        assert helper.batch_create_next_edges([]) is True
    
    def test_batch_create_actions_error_handling(self):
        """Test error handling in batch action creation."""
        # Mock driver that raises exception
        mock_driver = Mock()
        mock_session = Mock()
        mock_driver.session.return_value.__enter__ = Mock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = Mock(return_value=None)
        mock_session.run.side_effect = Exception("Database error")
        
        # Create helper and test
        helper = BatchNeo4jHelper(mock_driver)
        
        actions = [{"action_id": "action--1", "technique_id": "attack-pattern--1"}]
        result = helper.batch_create_attack_actions("episode--123", actions)
        
        # Should return False on error
        assert result is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])