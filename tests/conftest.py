from pathlib import Path

import pytest

DATASET_ROOT = Path(__file__).resolve().parents[1] / "dataset"


@pytest.fixture
def dataset_root() -> Path:
    return DATASET_ROOT
