from __future__ import annotations

import math
from typing import Dict, Iterable, List, Optional, Tuple


def _nan() -> float:
    return float("nan")


def safe_div(n: float, d: float) -> float:
    if d == 0 or math.isnan(d):
        return float("nan")
    return n / d


class OnlineStats:
    def __init__(self) -> None:
        self.n: int = 0
        self.mean: float = 0.0
        self.M2: float = 0.0

        # For higher moments/skewness and to allow median/percentiles we also keep samples
        self._vals: List[float] = []

        # Track min/max/sum explicitly
        self.minimum: float = math.inf
        self.maximum: float = -math.inf
        self.total_sum: float = 0.0

    def update(self, x: float) -> None:
        if x is None or math.isnan(x):
            return
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.M2 += delta * delta2
        self._vals.append(float(x))
        if x < self.minimum:
            self.minimum = x
        if x > self.maximum:
            self.maximum = x
        self.total_sum += x

    @property
    def variance(self) -> float:
        if self.n < 2:
            return float("nan")
        return self.M2 / (self.n - 1)

    @property
    def std(self) -> float:
        v = self.variance
        return math.sqrt(v) if not math.isnan(v) else float("nan")

    def _sorted(self) -> List[float]:
        return sorted(self._vals)

    def median(self) -> float:
        return percentile(self._vals, 50.0)

    def mode(self) -> float:
        return mode(self._vals)

    def skewness(self) -> float:
        # Compute from stored values to avoid numerical issues
        n = self.n
        if n < 3:
            return float("nan")
        m = self.mean
        s2 = self.variance
        if s2 == 0 or math.isnan(s2):
            return float("nan")
        s = math.sqrt(s2)
        m3 = sum((x - m) ** 3 for x in self._vals) / n
        return m3 / (s ** 3)

    def cov(self) -> float:
        if self.mean == 0:
            return float("nan")
        return self.std / abs(self.mean)

    def iqr(self) -> float:
        p25 = percentile(self._vals, 25.0)
        p75 = percentile(self._vals, 75.0)
        if math.isnan(p25) or math.isnan(p75):
            return float("nan")
        return p75 - p25

    def percentiles(self, ps: Iterable[float]) -> Dict[float, float]:
        return {p: percentile(self._vals, p) for p in ps}

    def to_dict(self, prefix: str, include_percentiles: bool = True) -> Dict[str, float]:
        out: Dict[str, float] = {
            f"{prefix}Mean": self.mean if self.n > 0 else float("nan"),
            f"{prefix}Std": self.std,
            f"{prefix}Max": self.maximum if self.n > 0 else float("nan"),
            f"{prefix}Min": self.minimum if self.n > 0 else float("nan"),
            f"{prefix}Sum": self.total_sum if self.n > 0 else 0.0,
            f"{prefix}Median": self.median(),
            f"{prefix}Skewness": self.skewness(),
            f"{prefix}CoV": self.cov(),
            f"{prefix}Variance": self.variance,
            f"{prefix}Mode": self.mode(),
        }
        if include_percentiles:
            for p in (10.0, 25.0, 50.0, 75.0, 90.0, 95.0):
                out[f"{prefix}P{int(p)}"] = percentile(self._vals, p)
        return out


def percentile(values: List[float], p: float) -> float:
    if not values:
        return float("nan")
    v = sorted(values)
    if p <= 0:
        return v[0]
    if p >= 100:
        return v[-1]
    k = (len(v) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return v[int(k)]
    d0 = v[int(f)] * (c - k)
    d1 = v[int(c)] * (k - f)
    return d0 + d1


def mode(values: List[float]) -> float:
    if not values:
        return float("nan")
    counts: Dict[float, int] = {}
    for x in values:
        counts[x] = counts.get(x, 0) + 1
    best_val: float = float("nan")
    best_count = -1
    for val, cnt in counts.items():
        if cnt > best_count or (cnt == best_count and (val < best_val or math.isnan(best_val))):
            best_val = val
            best_count = cnt
    return best_val


class SeriesStats:
    @staticmethod
    def from_list(values: List[float], prefix: str, include_percentiles: bool = True) -> Dict[str, float]:
        s = OnlineStats()
        for v in values:
            s.update(float(v))
        return s.to_dict(prefix, include_percentiles=include_percentiles)


