"""tools/try_h6_fixture.py runs the hunt 6 queries over VALUES fixtures; the warehouse run is manual, this checks
that the SQL is built from the hunt file and that the fixture holds the cases the guard is about."""
import importlib.util
from pathlib import Path

DEMO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("try_h6_fixture", DEMO / "tools" / "try_h6_fixture.py")
fx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fx)


def test_queries_read_only_the_fixture():
    for part in ("6a", "6b"):
        sql = fx.hunt_query(part)
        assert sql.startswith("WITH audit AS (") and "MATCH_RECOGNIZE" in sql
        assert "IDENTIFIER" not in sql and ":catalog" not in sql and ":schema" not in sql


def test_6a_cases():
    assert {a for a, (want, _) in fx.CASES_6A.items() if want} == {
        "batched@corp.example", "interleaved@corp.example", "relisting@corp.example"}
    rows = fx._rows()
    seq = [r[3] for r in rows if r[1] == "interleaved@corp.example" and r[3] in ("listSecrets", "getSecret")]
    assert seq == ["listSecrets", "getSecret"] * 3
    relist = [r[3] for r in rows if r[1] == "relisting@corp.example"]
    assert relist.count("listScopes") == 3  # discovery, harvest start, and again mid-harvest
    same = {r[3] for r in rows if r[1] == "same-discovery@corp.example" and r[0] < 300}
    assert same == {"tokenLogin", "listCatalogs"}
    assert all(r[8] != 200 for r in rows if r[1] == "no-good-read@corp.example" and r[3] == "getSecret")
    late = [r for r in rows if r[1] == "late-reads@corp.example"]
    assert fx.CASES_6A["late-reads@corp.example"][0] is False
    assert [r[0] for r in late if r[3] == "getSecret"] and all(r[0] > 30 * 60 for r in late if r[3] == "getSecret")
    assert all(r[0] <= 30 * 60 for r in late if r[3] != "getSecret")
