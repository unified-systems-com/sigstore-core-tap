"""Every dimension key this plugin declares has a Dimension node (unified-systems-com/tap#711).

Dimension nodes are declared, never minted on the fly: a key with no node is refused once the dimension
map keys by node id. This pins the seed to the plugin's keys.
"""

import json
from pathlib import Path

SEED = Path(__file__).resolve().parent.parent / "grift" / "dimension.grift.json"
EXPECTED = {"sigstore.ca_kind", "sigstore.log_kind", "sigstore.platform"}


def _dimension_nodes() -> list[dict]:
    doc = json.loads(SEED.read_text(encoding="utf-8"))
    return [n for batch in doc["batches"] for n in batch["nodes"] if n["entity"]["entity_type"] == "dimension"]


def test_every_declared_key_has_a_dimension_node() -> None:
    assert {n["node"]["name"] for n in _dimension_nodes()} == EXPECTED


def test_each_node_has_a_fixed_id_and_a_description() -> None:
    for node in _dimension_nodes():
        assert node["entity"]["entity_id"], node
        assert node["entity"]["name"] == node["node"]["name"]
        assert node["node"]["description"].strip(), node
