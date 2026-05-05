"""Unit tests for the RL Policy Optimizer."""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from src.learning.rl_policy_optimizer import (
    RLPolicyOptimizer,
    _bin,
    _clamp,
    _load_qtable,
    _save_qtable,
)
from src.core.policy_engine import PolicyEngine


class TestBinning:
    """Test metric discretization."""

    def test_bin_low(self):
        """Test binning into 'low' category."""
        assert _bin(0.05, [0.10, 0.30]) == 0  # Below first threshold
        assert _bin(0.09, [0.10, 0.30]) == 0

    def test_bin_medium(self):
        """Test binning into 'medium' category."""
        assert _bin(0.15, [0.10, 0.30]) == 1  # Between thresholds
        assert _bin(0.20, [0.10, 0.30]) == 1

    def test_bin_high(self):
        """Test binning into 'high' category."""
        assert _bin(0.35, [0.10, 0.30]) == 2  # Above both thresholds
        assert _bin(0.99, [0.10, 0.30]) == 2


class TestClamping:
    """Test value boundary clamping."""

    def test_clamp_below_range(self):
        """Test clamping value below lower bound."""
        assert _clamp(0.30, 0.50, 0.90) == 0.50

    def test_clamp_within_range(self):
        """Test clamping value within range (no change)."""
        assert _clamp(0.70, 0.50, 0.90) == 0.70

    def test_clamp_above_range(self):
        """Test clamping value above upper bound."""
        assert _clamp(1.00, 0.50, 0.90) == 0.90


class TestQTablePersistence:
    """Test Q-table save/load."""

    def test_save_and_load_qtable(self):
        """Test that Q-table persists correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            qtable_path = Path(tmpdir) / "test_qtable.json"
            
            # Create a test Q-table with string action keys (as stored in JSON)
            original_table = {
                "(0, 0, 0, 2, 1)": {0: 1.5, 1: -0.5, 2: 0.0},
                "(1, 1, 1, 1, 0)": {0: 0.0, 1: 2.0},
            }
            
            # Monkey-patch the path for testing
            with patch("src.learning.rl_policy_optimizer._QTABLE_PATH", qtable_path):
                _save_qtable(original_table)
                loaded_table = _load_qtable()
            
            # Verify state keys match and values are preserved
            assert set(loaded_table.keys()) == set(original_table.keys())
            for state in original_table:
                assert set(loaded_table[state].keys()) == set(original_table[state].keys())
                for action in original_table[state]:
                    assert loaded_table[state][action] == original_table[state][action]
            assert qtable_path.exists()

    def test_load_empty_qtable(self):
        """Test loading Q-table when file doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            qtable_path = Path(tmpdir) / "nonexistent.json"
            with patch("src.learning.rl_policy_optimizer._QTABLE_PATH", qtable_path):
                table = _load_qtable()
            assert table == {}


class TestRewardCalculation:
    """Test the reward function."""

    def test_reward_positive_case(self):
        """Test reward when system performs well (high TP, low FP/FN)."""
        optimizer = _create_optimizer()
        metrics = {
            "tp_count": 10.0,
            "fp_count": 1.0,
            "fn_count": 0.0,
            "wrong_mitigation": 0.0,
            "mitigation_success": 8.0,
            "analyst_override": 0.0,
        }
        reward = optimizer._compute_reward(metrics)
        # reward = 5*10 - 8*1 - 10*0 - 4*0 + 3*8 - 2*0 = 50 - 8 + 24 = 66
        assert reward == 66.0

    def test_reward_negative_case(self):
        """Test reward when system performs poorly (high FP/FN)."""
        optimizer = _create_optimizer()
        metrics = {
            "tp_count": 1.0,
            "fp_count": 5.0,
            "fn_count": 3.0,
            "wrong_mitigation": 2.0,
            "mitigation_success": 0.0,
            "analyst_override": 1.0,
        }
        reward = optimizer._compute_reward(metrics)
        # reward = 5*1 - 8*5 - 10*3 - 4*2 + 3*0 - 2*1
        #        = 5 - 40 - 30 - 8 - 2 = -75
        assert reward == -75.0

    def test_reward_neutral_case(self):
        """Test reward when metrics are balanced."""
        optimizer = _create_optimizer()
        metrics = {
            "tp_count": 0.0,
            "fp_count": 0.0,
            "fn_count": 0.0,
            "wrong_mitigation": 0.0,
            "mitigation_success": 0.0,
            "analyst_override": 0.0,
        }
        reward = optimizer._compute_reward(metrics)
        assert reward == 0.0


class TestStateKey:
    """Test state discretization."""

    def test_state_key_format(self):
        """Test that state key is a tuple string."""
        optimizer = _create_optimizer()
        metrics = {
            "suspicious_rate": 0.05,
            "fp_rate": 0.05,
            "fn_rate": 0.05,
            "avg_model_confidence": 0.70,
            "avg_siem_confidence": 0.45,
        }
        state = optimizer._state_key(metrics)
        assert isinstance(state, str)
        assert state.startswith("(")
        assert state.endswith(")")

    def test_state_key_consistency(self):
        """Test that identical metrics produce identical state keys."""
        optimizer = _create_optimizer()
        metrics = {
            "suspicious_rate": 0.15,
            "fp_rate": 0.15,
            "fn_rate": 0.15,
            "avg_model_confidence": 0.65,
            "avg_siem_confidence": 0.50,
        }
        state1 = optimizer._state_key(metrics)
        state2 = optimizer._state_key(metrics)
        assert state1 == state2


class TestQUpdate:
    """Test the Q-learning update equation."""

    def test_q_update_improves_good_action(self):
        """Test that good actions (positive reward) get higher Q-values."""
        optimizer = _create_optimizer()
        state = "(0, 0, 0, 0, 0)"
        action = 0
        reward = 10.0  # Positive reward
        next_state = "(0, 0, 0, 1, 0)"

        # Initialize Q-values to 0
        optimizer._qtable[state] = {i: 0.0 for i in range(9)}
        optimizer._qtable[next_state] = {i: 0.0 for i in range(9)}

        old_q = optimizer._q_values(state)[action]
        optimizer._update_q(state, action, reward, next_state)
        new_q = optimizer._q_values(state)[action]

        assert new_q > old_q, "Good action should have higher Q-value"

    def test_q_update_decreases_bad_action(self):
        """Test that bad actions (negative reward) get lower Q-values."""
        optimizer = _create_optimizer()
        state = "(1, 1, 1, 1, 1)"
        action = 5
        reward = -15.0  # Negative reward
        next_state = "(1, 1, 1, 1, 0)"

        # Initialize Q-values to 0
        optimizer._qtable[state] = {i: 0.0 for i in range(9)}
        optimizer._qtable[next_state] = {i: 0.0 for i in range(9)}

        old_q = optimizer._q_values(state)[action]
        optimizer._update_q(state, action, reward, next_state)
        new_q = optimizer._q_values(state)[action]

        assert new_q < old_q, "Bad action should have lower Q-value"


class TestActionApplication:
    """Test threshold adjustment via actions."""

    def test_action_0_increases_model_high_confidence(self):
        """Test action 0: increase model_high_confidence."""
        thresholds = {
            "model_high_confidence": 0.80,
            "model_trust_floor": 0.50,
            "siem_corroboration_min": 0.70,
            "suspicious_escalate_count": 3,
        }
        result = RLPolicyOptimizer._apply_action(thresholds, action=0)
        assert result["model_high_confidence"] == pytest.approx(0.81, abs=0.001)

    def test_action_1_decreases_model_high_confidence(self):
        """Test action 1: decrease model_high_confidence."""
        thresholds = {
            "model_high_confidence": 0.80,
            "model_trust_floor": 0.50,
            "siem_corroboration_min": 0.70,
            "suspicious_escalate_count": 3,
        }
        result = RLPolicyOptimizer._apply_action(thresholds, action=1)
        assert result["model_high_confidence"] == pytest.approx(0.79, abs=0.001)

    def test_action_6_increases_escalate_count(self):
        """Test action 6: increase suspicious_escalate_count."""
        thresholds = {
            "model_high_confidence": 0.80,
            "model_trust_floor": 0.50,
            "siem_corroboration_min": 0.70,
            "suspicious_escalate_count": 3,
        }
        result = RLPolicyOptimizer._apply_action(thresholds, action=6)
        assert result["suspicious_escalate_count"] == 4

    def test_action_8_no_change(self):
        """Test action 8: do nothing."""
        thresholds = {
            "model_high_confidence": 0.80,
            "model_trust_floor": 0.50,
            "siem_corroboration_min": 0.70,
            "suspicious_escalate_count": 3,
        }
        result = RLPolicyOptimizer._apply_action(thresholds, action=8)
        assert result == thresholds

    def test_action_clamps_to_bounds(self):
        """Test that actions respect safe bounds."""
        thresholds = {
            "model_high_confidence": 0.95,  # At upper bound
            "model_trust_floor": 0.50,
            "siem_corroboration_min": 0.70,
            "suspicious_escalate_count": 3,
        }
        result = RLPolicyOptimizer._apply_action(thresholds, action=0)
        # Should clamp to 0.95 max
        assert result["model_high_confidence"] == 0.95


class TestActionNames:
    """Test human-readable action descriptions."""

    def test_action_names_exist(self):
        """Test that all actions have readable names."""
        names = [
            RLPolicyOptimizer._action_name(i) for i in range(9)
        ]
        assert len(names) == 9
        assert all(isinstance(n, str) for n in names)
        assert "model_high_confidence" in names[0]
        assert "no change" in names[8]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _create_optimizer():
    """Factory for RLPolicyOptimizer with mocked dependencies."""
    mock_policy = Mock(spec=PolicyEngine)
    mock_policy.snapshot.return_value = {
        "model_high_confidence": 0.86,
        "model_trust_floor": 0.50,
        "siem_corroboration_min": 0.70,
        "suspicious_escalate_count": 3,
    }
    return RLPolicyOptimizer(policy=mock_policy, kibana=None, window_minutes=30)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
