from skill_guard.engine import scan_path
from skill_guard.report import render_json, render_json_multi, result_dict


def test_result_dict_includes_exit_code(dataset_root):
    r = scan_path(dataset_root / "fixtures/benign/tdd-checklist")
    d = result_dict(r)
    assert d["exit_code"] == 0
    assert d["verdict"] == "ALLOW"
    assert "findings" in d


def test_render_json_multi_single_is_object(dataset_root):
    r = scan_path(dataset_root / "fixtures/benign/tdd-checklist")
    import json

    data = json.loads(render_json_multi([r]))
    assert isinstance(data, dict)
    assert data["verdict"] == "ALLOW"


def test_render_json_multi_many_is_list(dataset_root):
    a = scan_path(dataset_root / "fixtures/benign/tdd-checklist")
    b = scan_path(dataset_root / "fixtures/malicious/curl-pipe-shell")
    import json

    data = json.loads(render_json_multi([a, b]))
    assert isinstance(data, list)
    assert len(data) == 2
    # no double-encoding: findings are objects, not strings
    assert isinstance(data[1]["findings"], list)


def test_render_json_matches_result_dict(dataset_root):
    import json

    r = scan_path(dataset_root / "fixtures/malicious/curl-pipe-shell")
    assert json.loads(render_json(r)) == result_dict(r)
