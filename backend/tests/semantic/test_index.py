"""Signals S5 and S6: approved mappings as examples of meanings, ranked by closeness, and
learning from an approval with no training step (kasauti/semantic/index.py)."""

from pathlib import Path

from kasauti.audit import load_kb
from kasauti.mapping.model import Mapping
from kasauti.semantic.embed import Embedder
from kasauti.semantic.index import SemanticIndex, keywords, label
from kasauti.studio.meanings import load_meanings
from kasauti.studio.workspace import suggest

PACKS = Path(__file__).resolve().parents[3] / "packs"


def _mappings() -> list[Mapping]:
    kb = load_kb(PACKS)
    return [m for p in kb.vendor_packs.values() for m in p.mappings]


def _by_id(mappings: list[Mapping], mapping_id: str) -> Mapping:
    return next(m for m in mappings if m.id == mapping_id)


def test_an_approved_mapping_is_an_example_of_the_meaning_its_effects_have() -> None:
    meanings = load_meanings()
    maps = _mappings()
    assert label(_by_id(maps, "cisco_ios_xe/vty-range-transport-input"), meanings) == (
        "line-protocols"
    )
    assert label(_by_id(maps, "cisco_ios_xe/interface"), meanings) == "interface"
    # Local accounts: no Studio meaning has these effects, so it teaches nothing.
    assert label(_by_id(maps, "cisco_ios_xe/enable-secret"), meanings) is None


def test_keywords_drop_values() -> None:
    assert keywords("logging host <IP:host> transport <STR:t>") == "logging host transport"


def test_a_line_ranks_nearest_the_meaning_other_vendors_approved(embedder: Embedder) -> None:
    index = SemanticIndex(embedder, load_meanings(), _mappings())
    # Huawei is in no seed pack; its words for a syslog server aren't Cisco's or Junos's.
    top = index.rank("info-center loghost")[0]
    assert top.meaning == "log-server"
    assert {e.vendor for e in top.examples} - {"huawei_vrp"}


def test_rare_words_weigh_more_than_common_ones(embedder: Embedder) -> None:
    index = SemanticIndex(embedder, load_meanings(), _mappings())
    (ip,) = embedder.pieces("ip")
    (host,) = embedder.pieces("host")
    assert index.weights[ip] < index.weights[host]


def test_an_approval_teaches_the_next_ranking_with_no_training_step(embedder: Embedder) -> None:
    """S6: a new vendor's approved line is an example as soon as the knowledge base holds it."""
    meanings = load_meanings()
    seeds = _mappings()
    query = "sysrec collector"
    before = [n.meaning for n in SemanticIndex(embedder, meanings, seeds).rank(query)]
    taught = Mapping.model_validate(
        {
            "id": "acme_os/sysrec-collector",
            "vendor": "acme_os",
            "entity": {"type": "LogTarget", "key": "{host}"},
            "match": "sysrec collector <IP:host> port <INT>",
            "effect": {"set": "LogTarget.host", "from": "host"},
            "provenance": {"version": 1, "proposed_by": "trainer:asha", "approved_by": ["x"]},
        }
    )
    after = [n.meaning for n in SemanticIndex(embedder, meanings, [*seeds, taught]).rank(query)]
    assert after[0] == "log-server"
    assert before.index("log-server") > 0


def test_a_negated_line_is_not_suggested_as_switching_on(embedder: Embedder) -> None:
    index = SemanticIndex(embedder, load_meanings(), _mappings())
    tokens = (("undo", None), ("http", None), ("server", None), ("enable", None))
    for idx in (None, index):
        got = suggest(tokens, None, load_meanings(), index=idx, negation=("undo",))
        assert got[0].meaning == "service-off"


def test_suggestions_say_which_signals_backed_them(embedder: Embedder) -> None:
    index = SemanticIndex(embedder, load_meanings(), _mappings())
    tokens = (("info-center", None), ("timestamp", None), ("log", None), ("date", None))
    top = suggest(tokens, None, load_meanings(), index=index)[0]
    assert top.meaning == "log-timestamps"
    assert set(top.signals) >= {"S1", "S4", "S5", "S6"}
    assert "'service timestamps log datetime' (cisco ios xe)" in top.why
