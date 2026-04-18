from __future__ import annotations

from .models import RegionRunState

SOFT_BACKOFF_GROWTH = 1.6
SOFT_BACKOFF_SCALE = 0.5
SOFT_BACKOFF_MIN_SECONDS = 1.0


def apply_batch_result(
    state: RegionRunState,
    *,
    created_count: int,
    match_count: int,
    miss_count: int,
    duplicate_count: int,
    deleted_count: int,
    min_batch_size: int,
    max_batch_size: int,
    cooldown_base: float,
    cooldown_max: float,
) -> float:
    state.batches += 1
    state.allocations += created_count
    state.matches += match_count
    state.misses += miss_count
    state.duplicates += duplicate_count
    state.deleted += deleted_count

    if match_count > 0:
        state.consecutive_matches += 1
        state.consecutive_misses = 0
        state.backoff_seconds = 0.0
        state.batch_size = min(max_batch_size, state.batch_size + max(1, match_count))
        state.last_result = "match"
        return 0.0

    state.consecutive_matches = 0
    state.consecutive_misses += 1

    if created_count <= 0:
        state.batch_size = max(min_batch_size, state.batch_size // 2)
        state.backoff_seconds = _soft_backoff(state.backoff_seconds, cooldown_base, cooldown_max)
        state.last_result = "empty"
        return state.backoff_seconds

    duplicate_ratio = duplicate_count / max(created_count, 1)
    if duplicate_ratio >= 0.5:
        state.batch_size = max(min_batch_size, state.batch_size // 2)
        state.backoff_seconds = _soft_backoff(state.backoff_seconds, cooldown_base, cooldown_max)
        state.last_result = "duplicate-heavy"
        return state.backoff_seconds

    if miss_count == created_count:
        state.batch_size = min(max_batch_size, state.batch_size + 1)
        state.backoff_seconds = 0.0
        state.last_result = "all-miss"
        return 0.0

    state.backoff_seconds = _soft_seed(cooldown_base) if duplicate_count > 0 else 0.0
    state.last_result = "mixed"
    return state.backoff_seconds


def apply_error(
    state: RegionRunState,
    *,
    error_message: str,
    min_batch_size: int,
    cooldown_base: float,
    cooldown_max: float,
) -> float:
    state.errors += 1
    state.last_error = error_message
    state.last_result = "error"
    state.consecutive_matches = 0
    state.consecutive_misses += 1
    state.batch_size = max(min_batch_size, state.batch_size // 2)
    state.backoff_seconds = _next_backoff(state.backoff_seconds, cooldown_base, cooldown_max)
    return state.backoff_seconds


def _soft_backoff(current: float, base: float, max_value: float) -> float:
    return _next_backoff(
        current,
        _soft_seed(base),
        max_value,
        growth=SOFT_BACKOFF_GROWTH,
    )


def _soft_seed(base: float) -> float:
    if base <= 0:
        return 0.0
    return max(SOFT_BACKOFF_MIN_SECONDS, base * SOFT_BACKOFF_SCALE)


def _next_backoff(current: float, base: float, max_value: float, *, growth: float = 2.0) -> float:
    if base <= 0:
        return 0.0
    if current > 0:
        return min(max_value, current * max(1.0, growth))
    return min(max_value, base)
