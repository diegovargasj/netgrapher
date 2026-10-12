import pytest

from netgrapher.infer.confidence import noisy_or


def test_noisy_or() -> None:
    assert noisy_or([]) == 0.0
    assert noisy_or([1.0, 0.2]) == 1.0
    assert noisy_or([0.5, 0.5]) == pytest.approx(0.75)


def test_noisy_or_rejects_out_of_range() -> None:
    with pytest.raises(ValueError):
        noisy_or([1.5])
