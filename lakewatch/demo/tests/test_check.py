"""The scenario x rule matrix of a reset (Review Focus 2)."""

from __future__ import annotations

from dataclasses import dataclass, field

from auditdemo import check
from auditdemo.scenarios import ALL
from auditdemo.world import World

WORLD = World(1337)


@dataclass
class Sc:
    key: str
    who: set[str]
    expected_rules: set[str]
    forbidden_rules: set[str] = field(default_factory=set)

    def actors(self, world):
        return self.who


A = Sc("A", {"maria@x", "sp-uuid"}, {"ada_one", "ada_two", "ada_pivot", "adp_pack"})
B = Sc("B", {"tom@x"}, {"ada_three"})
D = Sc("D", {"ci-uuid"}, {"adp_pack"}, {"ada_one", "ada_two", "ada_three"})
SCENARIOS = [A, B, D]
OK = [("ada_one", "maria@x"), ("ada_two", "sp-uuid"), ("ada_pivot", "maria@x, sp-uuid"),
      ("adp_pack", "maria@x"), ("ada_three", "tom@x"), ("adp_pack", "ci-uuid")]


def test_matrix_ok():
    assert check.matrix(OK, SCENARIOS, WORLD) == []


def test_matrix_ok_with_duplicates_and_noisy_ported_rule():
    # adp_ rules may fire on background actors: they are the noisy single-event layer.
    signals = OK + OK + [("adp_pack", "someone@x"), ("adp_other", "bg@x")]
    assert check.matrix(signals, SCENARIOS, WORLD) == []


def test_matrix_missing_expected():
    problems = check.matrix([s for s in OK if s[0] != "ada_three"], SCENARIOS, WORLD)
    assert problems == ["B: expected ada_three, no signal from tom@x"]


def test_matrix_missing_when_only_another_scenario_fires():
    # ada_one fired, but from B's actor: A still misses it, and the signal is foreign.
    signals = [s for s in OK if s[0] != "ada_one"] + [("ada_one", "tom@x")]
    problems = check.matrix(signals, SCENARIOS, WORLD)
    assert any(p.startswith("A: expected ada_one") for p in problems)
    assert any(p.startswith("foreign signal: ada_one from tom@x") for p in problems)


def test_matrix_foreign_actor():
    # A stage-rule signal from a background actor is a problem (Review Focus 2).
    problems = check.matrix(OK + [("ada_one", "bg-user@x")], SCENARIOS, WORLD)
    assert problems == ["foreign signal: ada_one from bg-user@x (no scenario that expects ada_one has this actor)"]


def test_matrix_foreign_unexpected_ada_rule():
    problems = check.matrix(OK + [("ada_never", "maria@x")], SCENARIOS, WORLD)
    assert problems == ["foreign signal: ada_never from maria@x (no scenario that expects ada_never has this actor)"]


def test_matrix_correlation_matches_any_actor_of_the_scenario():
    assert check.matrix(OK + [("ada_pivot", "bg1@x, sp-uuid")], SCENARIOS, WORLD) == []
    assert check.matrix(OK + [("ada_pivot", "bg1@x, bg2@x")], SCENARIOS, WORLD) != []


def test_matrix_forbidden_decoy():
    problems = check.matrix(OK + [("ada_two", "ci-uuid")], SCENARIOS, WORLD)
    assert "D: forbidden ada_two fired for ci-uuid" in problems


def test_matrix_real_scenarios_need_all_expected():
    problems = check.matrix([], ALL, WORLD)
    assert len(problems) == sum(len(s.expected_rules) for s in ALL)


def test_matrix_real_scenarios_ok():
    signals = [(r, sorted(s.actors(WORLD))[0]) for s in ALL for r in s.expected_rules]
    assert check.matrix(signals, ALL, WORLD) == []


def test_expected_rules_of_scenarios():
    assert check.expected_rules(ALL) == sorted({r for s in ALL for r in s.expected_rules})
