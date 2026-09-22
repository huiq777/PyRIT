# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Typed signal for attacks that ended before the objective target could be measured."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from pyrit.models import AttackResult


class AttackPreparationFailureKind(str, enum.Enum):
    """
    Why an attack terminated before it could send anything to the objective target.

    Inherits from ``str`` so the value round-trips through ``AttackResult.metadata``
    persistence without a dedicated mapping function.
    """

    #: The adversarial chat's own response was blocked by its provider's content policy,
    #: so no attacker turn could be generated. This is a property of the adversarial
    #: model's deployment, not a measurement of the objective target.
    ADVERSARIAL_CHAT_BLOCKED = "adversarial_chat_blocked"

    @property
    def default_reason(self) -> str:
        """
        Human-readable description used when a result carries the signal but no outcome reason.

        Returns:
            str: A non-empty description of this failure kind.
        """
        if self is AttackPreparationFailureKind.ADVERSARIAL_CHAT_BLOCKED:
            return "Adversarial chat was blocked by its provider before the attack could run."
        return "The attack could not be prepared."


@dataclass(frozen=True)
class AttackPreparationFailure:
    """
    A typed record that an attack never reached the objective target.

    Attacks carry this on ``AttackResult.metadata`` instead of an ad-hoc string key so
    that producers (``RedTeamingAttack``, ``PromptSendingAttack``) and consumers
    (``generate_simulated_conversation_async``, result auditing) share one contract and
    neither depends on the other's module. Results carrying it use
    ``AttackOutcome.UNDETERMINED``: no verdict about the objective target was reached, so
    the row is not a measured failure and must not be reused as one.
    """

    kind: AttackPreparationFailureKind
    reason: str

    #: Key under which the signal travels in ``AttackResult.metadata``.
    METADATA_KEY: ClassVar[str] = "attack_preparation_failure"

    def __post_init__(self) -> None:
        """
        Enforce that a failure always carries a usable description.

        Raises:
            ValueError: If ``reason`` is empty.
        """
        if not self.reason:
            raise ValueError("AttackPreparationFailure requires a non-empty reason.")

    def to_metadata(self) -> dict[str, Any]:
        """
        Render the signal for ``AttackResult.metadata``.

        Returns:
            dict[str, Any]: The metadata fragment identifying this failure kind.
        """
        return {self.METADATA_KEY: self.kind.value}

    @classmethod
    def from_result(cls, *, result: AttackResult) -> AttackPreparationFailure | None:
        """
        Read the signal back off a result.

        Args:
            result (AttackResult): The result to inspect.

        Returns:
            AttackPreparationFailure | None: The recorded failure with a guaranteed
            non-empty ``reason``, or ``None`` when the result carries no recognized signal.
        """
        raw_kind = result.metadata.get(cls.METADATA_KEY)
        if raw_kind is None:
            return None
        try:
            kind = AttackPreparationFailureKind(raw_kind)
        except ValueError:
            return None
        return cls(kind=kind, reason=result.outcome_reason or kind.default_reason)
