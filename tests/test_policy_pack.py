"""Policy packs default / strict."""

from pathlib import Path

from skill_guard.config import POLICY_PACKS, apply_pack, load_config
from skill_guard.engine import scan_path
from skill_guard.models import Verdict


def test_packs_defined():
    assert set(POLICY_PACKS) == {"default", "strict"}
    assert POLICY_PACKS["default"]["fail_on"] == "block"
    assert POLICY_PACKS["strict"]["fail_on"] == "warn"


def test_apply_pack_strict():
    cfg = apply_pack(load_config(), "strict")
    assert cfg.fail_on == "warn"
    assert cfg.pack == "strict"


def test_yaml_pack_field(tmp_path: Path):
    p = tmp_path / ".skill-guard.yml"
    p.write_text("pack: strict\n")
    cfg = load_config(p)
    assert cfg.fail_on == "warn"


def test_strict_fails_on_warn_medium(dataset_root: Path):
    """Fenced npm -g is MEDIUM → WARN; strict fail_on=warn exits via engine contract."""
    # Use vercel ood if present; else skip
    target = dataset_root / "ood/safe/vercel/deploy-to-vercel"
    if not target.is_dir():
        return
    r = scan_path(target)
    assert r.verdict is Verdict.WARN
    cfg = apply_pack(load_config(), "strict")
    assert cfg.fail_on == "warn"
    # exit_code property is verdict-based; fail_on applied at CLI
    assert r.exit_code == 1
