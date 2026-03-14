"""Public exports for agent classes.

Lazy imports are used to avoid circular imports during package initialization.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.agents.intrusion_classification_agent import (  # pragma: no cover
        IntrusionClassificationAgent,
        ClassificationResult,
    )


def __getattr__(name: str):
    if name in {"IntrusionClassificationAgent", "ClassificationResult"}:
        from src.agents.intrusion_classification_agent import (
            IntrusionClassificationAgent,
            ClassificationResult,
        )
        return {
            "IntrusionClassificationAgent": IntrusionClassificationAgent,
            "ClassificationResult": ClassificationResult,
        }[name]
    raise AttributeError(name)


__all__ = ["IntrusionClassificationAgent", "ClassificationResult"]
