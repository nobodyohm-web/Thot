"""A goal that survives compaction, and a budget that cannot be exceeded quietly.

Prime Agent's model, ported: an agent told to keep going until something is
true needs the "something" stored somewhere other than the conversation it
is about to compact away.
"""

from __future__ import annotations

import pytest

from thot.state import SessionStore


@pytest.fixture
def store(tmp_path):
    store = SessionStore.open(tmp_path / "sessions.db")
    yield store
    store.close()


def test_a_goal_belongs_to_the_repository_not_to_the_session(store):
    store.set_goal("/repo", "plus aucun HIGH dans le parseur")

    assert store.goal("/repo").objective == "plus aucun HIGH dans le parseur"
    assert store.goal("/autre") is None


def test_only_one_goal_is_live_at_a_time(store):
    first = store.set_goal("/repo", "premier objectif")
    second = store.set_goal("/repo", "second objectif")

    assert store.goal("/repo").id == second.id
    history = {g.id: g.status for g in store.goal_history("/repo")}
    assert history[first.id] == "abandoned"


def test_an_empty_or_oversized_objective_is_refused(store):
    with pytest.raises(ValueError):
        store.set_goal("/repo", "   ")
    with pytest.raises(ValueError):
        store.set_goal("/repo", "x" * 5000)
    with pytest.raises(ValueError):
        store.set_goal("/repo", "correct", token_budget=0)


def test_running_out_of_budget_is_a_state_not_an_error(store):
    """The turn that crossed the line already happened; the user is owed a report."""
    goal = store.set_goal("/repo", "auditer", token_budget=1000)

    assert store.charge_goal(goal.id, 400).status == "active"
    stopped = store.charge_goal(goal.id, 700)

    assert stopped.status == "budget_limited"
    assert stopped.remaining == 0
    assert stopped.calls_used == 2
    assert stopped.live, "un objectif stoppé reste l'objectif en cours"


def test_the_briefing_tells_the_model_to_stop_starting_things(store):
    goal = store.set_goal("/repo", "auditer", token_budget=100)
    stopped = store.charge_goal(goal.id, 200)

    brief = stopped.brief()
    assert "auditer" in brief
    assert "budget est épuisé" in brief
    assert "N'entame rien de nouveau" in brief


def test_raising_the_budget_puts_a_stopped_goal_back_to_work(store):
    goal = store.set_goal("/repo", "auditer", token_budget=100)
    store.charge_goal(goal.id, 200)

    revived = store.raise_goal_budget(goal.id, 5000)
    assert revived.status == "active"
    assert revived.remaining == 4800


def test_a_goal_without_a_budget_never_stops_itself(store):
    goal = store.set_goal("/repo", "explorer")
    charged = store.charge_goal(goal.id, 10_000_000)

    assert charged.status == "active"
    assert charged.remaining is None


def test_finishing_clears_the_live_goal_but_keeps_the_record(store):
    goal = store.set_goal("/repo", "auditer")
    store.finish_goal(goal.id, "complete")

    assert store.goal("/repo") is None
    assert [g.status for g in store.goal_history("/repo")] == ["complete"]


def test_a_paused_goal_says_so_and_stays_current(store):
    goal = store.set_goal("/repo", "auditer")
    store.pause_goal(goal.id)

    current = store.goal("/repo")
    assert current.status == "paused"
    assert "pause" in current.brief()
