"""The scenario x rule matrix: do the signals of a reset match the planted scenarios?

Input: the distinct (rule, actor) pairs of the signals created since the reset. For correlation rules
the actor is the `actors` context value, a comma-separated list of identities; it matches a scenario
when any of them belongs to the scenario.

Problems:
- an expected rule of a scenario has no signal from the scenario's actors;
- an `ada_*` signal whose actors belong to no scenario that expects the rule (Review Focus 2: the
  background must not fire the stage or correlation rules). `adp_*` rules are the noisy single-event
  layer and may fire on background actors: that noise is the contrast the demo shows;
- a forbidden rule of a scenario (the decoys) has a signal from the scenario's actors.
"""

from __future__ import annotations

from collections.abc import Iterable


def _actors(actor: str | None) -> set[str]:
    return {a.strip() for a in (actor or "").split(",") if a.strip()}


def expected_rules(scenarios) -> list[str]:
    return sorted({r for s in scenarios for r in s.expected_rules})


def matrix(signals: Iterable[tuple[str, str]], scenarios, world) -> list[str]:
    pairs = sorted({(rule, actor or "") for rule, actor in signals})
    who = {s.key: s.actors(world) for s in scenarios}
    problems = []
    for s in scenarios:
        mine = who[s.key]
        for rule in sorted(s.expected_rules):
            if not any(r == rule and _actors(a) & mine for r, a in pairs):
                problems.append(f"{s.key}: expected {rule}, no signal from {', '.join(sorted(mine))}")
    for rule, actor in pairs:
        if not rule.startswith("ada_"):
            continue
        if not any(rule in s.expected_rules and _actors(actor) & who[s.key] for s in scenarios):
            problems.append(f"foreign signal: {rule} from {actor or '(no actor)'} "
                            f"(no scenario that expects {rule} has this actor)")
    for s in scenarios:
        for rule, actor in pairs:
            hit = _actors(actor) & who[s.key]
            if rule in s.forbidden_rules and hit:
                problems.append(f"{s.key}: forbidden {rule} fired for {', '.join(sorted(hit))}")
    return problems


def table(signals: Iterable[tuple[str, str]], scenarios, world) -> list[tuple[str, str, int]]:
    """(scenario or 'background', rule, distinct actor count) for a printout of the run."""
    pairs = sorted({(rule, actor or "") for rule, actor in signals})
    who = {s.key: s.actors(world) for s in scenarios}
    out: dict[tuple[str, str], set[str]] = {}
    for rule, actor in pairs:
        keys = [k for k, mine in who.items() if _actors(actor) & mine] or ["background"]
        for k in keys:
            out.setdefault((k, rule), set()).add(actor)
    return [(k, r, len(a)) for (k, r), a in sorted(out.items())]
