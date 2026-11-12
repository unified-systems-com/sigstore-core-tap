"""Every dimension key this plugin declares has a Dimension node with a fixed id (unified-systems-com/tap#711).

Dimension nodes are declared, never minted on the fly: once the dimension map keys by node id, a key
with no node is refused. The declared keys are read from the plugin's own source (every
``DEFAULT_DIMENSIONS`` assignment, resolving a module-level dict it names, and every edge's
``default_dimensions``), so a new key without a node fails here. The ids are pinned, because the
map stores them and a regenerated id would orphan every row that carries the old one.
"""

import ast
import json
import uuid
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent
SEED = PACKAGE / "grift" / "dimension.grift.json"
PINNED = {
    "sigstore.ca_kind": "01a1d10a-f0af-71cc-af14-cf5740b9afcb",
    "sigstore.log_kind": "01a1d10a-f0af-71cc-af14-cf58341bc65a",
    "sigstore.platform": "01a1d10a-f0af-71cc-af14-cf56ff1ac14b",
}


def _dimension_nodes() -> list[dict]:
    doc = json.loads(SEED.read_text(encoding="utf-8"))
    return [n for batch in doc["batches"] for n in batch["nodes"] if n["entity"]["entity_type"] == "dimension"]


def _dict_keys(node: ast.AST, named: dict[str, ast.AST]) -> set[str]:
    if isinstance(node, ast.Dict):
        return {k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    if isinstance(node, ast.Name) and node.id in named:
        return _dict_keys(named[node.id], named)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict" and node.args:
        return _dict_keys(node.args[0], named)
    if isinstance(node, ast.BinOp):  # {**a, **b} spelled a | b
        return _dict_keys(node.left, named) | _dict_keys(node.right, named)
    return set()


def _declared_keys() -> set[str]:
    sources = [p for p in PACKAGE.rglob("*.py") if "tests" not in p.parts and "migrations" not in p.parts]
    trees = [ast.parse(p.read_text(encoding="utf-8")) for p in sources]
    named: dict[str, ast.AST] = {}
    for tree in trees:
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign | ast.AnnAssign) and stmt.value is not None:
                for target in stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]:
                    if isinstance(target, ast.Name):
                        named[target.id] = stmt.value
    keys: set[str] = set()
    for tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign | ast.AnnAssign) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(isinstance(t, ast.Name) and t.id == "DEFAULT_DIMENSIONS" for t in targets):
                    keys |= _dict_keys(node.value, named)
    for edge in PACKAGE.rglob("*.edge.json"):
        keys |= set(json.loads(edge.read_text(encoding="utf-8")).get("default_dimensions") or {})
    return keys


def test_every_declared_key_has_a_dimension_node() -> None:
    names = {n["node"]["name"] for n in _dimension_nodes()}
    missing = _declared_keys() - names
    assert not missing, f"declared dimension keys with no Dimension node in {SEED.name}: {sorted(missing)}"


def test_the_seed_ids_are_pinned_uuid7s() -> None:
    nodes = _dimension_nodes()
    assert {n["node"]["name"]: n["entity"]["entity_id"] for n in nodes} == PINNED
    for node in nodes:
        assert uuid.UUID(node["entity"]["entity_id"]).version == 7, node["entity"]["entity_id"]
        assert node["entity"]["name"] == node["node"]["name"]
        assert node["node"]["description"].strip(), node
