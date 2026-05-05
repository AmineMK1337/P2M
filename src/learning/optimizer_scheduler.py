"""
src/learning/optimizer_scheduler.py
─────────────────────────────────────
Runs RLPolicyOptimizer.run_cycle() every `interval_seconds` seconds
in a daemon background thread.  The main packet-processing loop is
never blocked.

Usage (see src/main.py):

    from src.core.policy_engine import PolicyEngine
    from src.learning.rl_policy_optimizer import RLPolicyOptimizer
    from src.learning.optimizer_scheduler import OptimizerScheduler

    policy    = PolicyEngine()
    optimizer = RLPolicyOptimizer(policy=policy, kibana=kibana)
    scheduler = OptimizerScheduler(optimizer)
    scheduler.start()                    # non-blocking — returns immediately

    # ... rest of startup ...

    # Optional clean shutdown:
    scheduler.stop()
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_INTERVAL = 600  # 10 minutes


class OptimizerScheduler:
    """
    Background scheduler for the RL policy optimizer.

    Parameters
    ----------
    optimizer:
        An RLPolicyOptimizer instance.
    interval_seconds:
        How often to run an optimization cycle.  Default: 600 s (10 min).
    """

    def __init__(
        self,
        optimizer,                           # RLPolicyOptimizer — loose type to avoid circular import
        interval_seconds: int = _DEFAULT_INTERVAL,
    ) -> None:
        self._optimizer = optimizer
        self._interval = interval_seconds
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Launch the background optimization loop.
        Returns immediately — the loop runs in a daemon thread.
        """
        if self._thread is not None and self._thread.is_alive():
            logger.warning("[RL-OPTIMIZER] Scheduler already running — ignoring start()")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="rl-policy-optimizer",
            daemon=True,   # exits automatically when the main process dies
        )
        self._thread.start()
        logger.info(
            "[RL-OPTIMIZER] Scheduler started — cycle every %d s (%d min)",
            self._interval,
            self._interval // 60,
        )

    def stop(self) -> None:
        """Signal the background thread to stop after the current cycle."""
        self._stop_event.set()
        logger.info("[RL-OPTIMIZER] Scheduler stop requested.")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ── Internal loop ─────────────────────────────────────────────────────────

    def _loop(self) -> None:
        """
        Blocking loop that runs inside the daemon thread.
        Uses threading.Event.wait() so it wakes up immediately on stop().
        """
        logger.info("[RL-OPTIMIZER] Background loop entered.")

        while not self._stop_event.wait(timeout=self._interval):
            try:
                logger.info("[RL-OPTIMIZER] Starting optimization cycle …")
                self._optimizer.run_cycle()
            except Exception as exc:
                # Log and continue — a bad cycle must not kill the thread
                logger.exception("[RL-OPTIMIZER] Cycle raised an unhandled exception: %s", exc)

        logger.info("[RL-OPTIMIZER] Background loop exiting.")
