"""
Real-Time Anomaly Detector
===========================
Streams synthetic sensor/telemetry data through an ensemble of anomaly
detection algorithms and flags anomalies in real time using asyncio.

Features:
  - Async data stream producer (simulates IoT/telemetry feed)
  - Ensemble detector: Isolation Forest + Z-Score + EWMA control chart
  - Sliding window buffer for online learning
  - Live console dashboard with colorized output
  - Prometheus-style metrics counters
  - Saves anomaly log to CSV

Usage:
    python 03_realtime_anomaly_detector.py --duration 60 --rate 10

Requirements:
    pip install numpy pandas scikit-learn rich
"""

import argparse
import asyncio
import csv
import math
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import AsyncGenerator, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("[Warning] 'rich' not installed — falling back to plain console.")


# ---------------------------------------------------------------------------
# Data stream simulator
# ---------------------------------------------------------------------------

@dataclass
class StreamConfig:
    rate_hz:          float = 10.0    # data points per second
    n_features:       int   = 5       # number of sensor channels
    anomaly_prob:     float = 0.03    # probability of injecting an anomaly
    noise_std:        float = 0.3     # background Gaussian noise
    drift_rate:       float = 0.001   # slow concept drift per sample
    seed:             int   = 42


class SensorStreamSimulator:
    """
    Simulates a multi-channel sensor feed with:
      - Sinusoidal base signals (different frequency per channel)
      - Gaussian noise
      - Slow seasonal drift
      - Random anomaly spikes / drops
    """

    def __init__(self, cfg: StreamConfig):
        self.cfg      = cfg
        self.t        = 0.0
        self.drift    = 0.0
        self.rng      = np.random.default_rng(cfg.seed)
        self.freqs    = self.rng.uniform(0.1, 0.5, cfg.n_features)
        self.phases   = self.rng.uniform(0, 2 * math.pi, cfg.n_features)
        self.amps     = self.rng.uniform(1.0, 3.0, cfg.n_features)

    def next_sample(self) -> Tuple[np.ndarray, bool]:
        """Return (feature_vector, is_true_anomaly)."""
        dt      = 1.0 / self.cfg.rate_hz
        self.t += dt
        self.drift += self.cfg.drift_rate

        base = np.array([
            self.amps[i] * math.sin(2 * math.pi * self.freqs[i] * self.t + self.phases[i])
            for i in range(self.cfg.n_features)
        ])
        noise = self.rng.normal(0, self.cfg.noise_std, self.cfg.n_features)
        x     = base + noise + self.drift

        is_anomaly = self.rng.random() < self.cfg.anomaly_prob
        if is_anomaly:
            # Random channel spike or collective drop
            anomaly_type = self.rng.choice(["spike", "drop", "collective"])
            if anomaly_type == "spike":
                channel = self.rng.integers(0, self.cfg.n_features)
                x[channel] += self.rng.uniform(5, 10)
            elif anomaly_type == "drop":
                channel = self.rng.integers(0, self.cfg.n_features)
                x[channel] -= self.rng.uniform(5, 10)
            else:
                x += self.rng.uniform(-4, 4, self.cfg.n_features)

        return x, is_anomaly

    async def stream(self, duration_s: float) -> AsyncGenerator[Tuple[float, np.ndarray, bool], None]:
        """Async generator: yields (timestamp, feature_vector, is_true_anomaly)."""
        start = time.time()
        interval = 1.0 / self.cfg.rate_hz
        while time.time() - start < duration_s:
            t_start = asyncio.get_event_loop().time()
            x, label = self.next_sample()
            yield time.time(), x, label
            elapsed = asyncio.get_event_loop().time() - t_start
            await asyncio.sleep(max(0, interval - elapsed))


# ---------------------------------------------------------------------------
# Anomaly detection algorithms
# ---------------------------------------------------------------------------

class ZScoreDetector:
    """Online Z-score detector with exponential moving stats."""

    def __init__(self, alpha: float = 0.05, threshold: float = 3.5):
        self.alpha     = alpha
        self.threshold = threshold
        self.mean_: Optional[np.ndarray] = None
        self.var_:  Optional[np.ndarray] = None

    def update_predict(self, x: np.ndarray) -> Tuple[bool, np.ndarray]:
        if self.mean_ is None:
            self.mean_ = x.copy()
            self.var_  = np.ones_like(x)
            return False, np.zeros_like(x)

        z_scores = np.abs((x - self.mean_) / (np.sqrt(self.var_) + 1e-9))
        is_anomaly = bool(np.any(z_scores > self.threshold))

        # EMA update
        self.mean_ = self.alpha * x + (1 - self.alpha) * self.mean_
        self.var_  = self.alpha * (x - self.mean_) ** 2 + (1 - self.alpha) * self.var_
        return is_anomaly, z_scores


class EWMAControlChart:
    """EWMA (Exponentially Weighted Moving Average) control chart."""

    def __init__(self, lambda_: float = 0.2, L: float = 3.0):
        self.lambda_ = lambda_
        self.L       = L
        self.ewma_:  Optional[np.ndarray] = None
        self.sigma_: Optional[float]      = None
        self._samples: List[np.ndarray]   = []

    def update_predict(self, x: np.ndarray) -> bool:
        self._samples.append(x)

        if len(self._samples) < 20:
            self.ewma_ = x.copy() if self.ewma_ is None else (
                self.lambda_ * x + (1 - self.lambda_) * self.ewma_
            )
            return False

        if self.sigma_ is None:
            arr = np.array(self._samples)
            self.sigma_ = float(np.std(arr))

        prev_ewma = self.ewma_.copy()
        self.ewma_ = self.lambda_ * x + (1 - self.lambda_) * prev_ewma

        n  = len(self._samples)
        ucl_var = (self.lambda_ / (2 - self.lambda_)) * (1 - (1 - self.lambda_) ** (2 * n))
        ucl = self.L * self.sigma_ * math.sqrt(ucl_var)

        deviation = float(np.max(np.abs(self.ewma_ - prev_ewma)))
        return deviation > ucl + 1e-9


class IsolationForestDetector:
    """
    Isolation Forest that re-trains on a sliding window of clean data.
    """

    def __init__(self, window: int = 300, contamination: float = 0.05, retrain_every: int = 50):
        self.window        = window
        self.contamination = contamination
        self.retrain_every = retrain_every
        self.buffer: deque = deque(maxlen=window)
        self.model:  Optional[IsolationForest] = None
        self.scaler: StandardScaler = StandardScaler()
        self._n     = 0
        self._trained = False

    def update_predict(self, x: np.ndarray) -> Tuple[bool, float]:
        self.buffer.append(x)
        self._n += 1

        # Need minimum data before first training
        if len(self.buffer) < 50:
            return False, 0.0

        # Retrain periodically
        if self._n % self.retrain_every == 0 or not self._trained:
            data = np.array(self.buffer)
            self.scaler.fit(data)
            X_scaled = self.scaler.transform(data)
            self.model = IsolationForest(
                n_estimators=100,
                contamination=self.contamination,
                random_state=42,
            ).fit(X_scaled)
            self._trained = True

        if not self._trained:
            return False, 0.0

        x_scaled = self.scaler.transform(x.reshape(1, -1))
        score    = float(self.model.score_samples(x_scaled)[0])   # more negative = more anomalous
        label    = int(self.model.predict(x_scaled)[0]) == -1
        return label, score


# ---------------------------------------------------------------------------
# Ensemble detector
# ---------------------------------------------------------------------------

@dataclass
class AnomalyEvent:
    timestamp: float
    features:  np.ndarray
    z_score:   bool
    ewma:      bool
    iso_forest: bool
    iso_score: float
    true_label: bool

    @property
    def ensemble_vote(self) -> bool:
        """Majority vote: at least 2 of 3 detectors agree."""
        return sum([self.z_score, self.ewma, self.iso_forest]) >= 2


class EnsembleAnomalyDetector:
    def __init__(self):
        self.zscore  = ZScoreDetector(alpha=0.03, threshold=3.5)
        self.ewma    = EWMAControlChart(lambda_=0.2, L=3.0)
        self.iso     = IsolationForestDetector(window=300, contamination=0.05)

    def detect(self, x: np.ndarray, ts: float, true_label: bool) -> AnomalyEvent:
        z_flag, _   = self.zscore.update_predict(x)
        e_flag      = self.ewma.update_predict(x)
        i_flag, i_s = self.iso.update_predict(x)
        return AnomalyEvent(
            timestamp=ts, features=x,
            z_score=z_flag, ewma=e_flag,
            iso_forest=i_flag, iso_score=i_s,
            true_label=true_label,
        )


# ---------------------------------------------------------------------------
# Metrics tracker
# ---------------------------------------------------------------------------

@dataclass
class Metrics:
    total:     int = 0
    detected:  int = 0
    true_pos:  int = 0
    false_pos: int = 0
    true_neg:  int = 0
    false_neg: int = 0

    def update(self, event: AnomalyEvent) -> None:
        self.total += 1
        pred = event.ensemble_vote
        true = event.true_label
        if pred:  self.detected += 1
        if pred and true:  self.true_pos  += 1
        if pred and not true: self.false_pos += 1
        if not pred and not true: self.true_neg  += 1
        if not pred and true:  self.false_neg += 1

    @property
    def precision(self) -> float:
        d = self.true_pos + self.false_pos
        return self.true_pos / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.true_pos + self.false_neg
        return self.true_pos / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


# ---------------------------------------------------------------------------
# Console display
# ---------------------------------------------------------------------------

def make_status_table(metrics: Metrics, recent: List[AnomalyEvent]) -> "Table":
    table = Table(title="Real-Time Anomaly Detector", show_header=True)
    table.add_column("Metric",    style="cyan",  width=20)
    table.add_column("Value",     style="white", width=12)

    table.add_row("Samples processed", str(metrics.total))
    table.add_row("Anomalies detected", str(metrics.detected))
    table.add_row("True Positives",  str(metrics.true_pos))
    table.add_row("False Positives", str(metrics.false_pos))
    table.add_row("Precision", f"{metrics.precision:.3f}")
    table.add_row("Recall",    f"{metrics.recall:.3f}")
    table.add_row("F1 Score",  f"{metrics.f1:.3f}")

    return table


# ---------------------------------------------------------------------------
# Main async loop
# ---------------------------------------------------------------------------

async def run_detector(duration: float, rate: float, output_csv: str) -> None:
    cfg      = StreamConfig(rate_hz=rate)
    stream   = SensorStreamSimulator(cfg)
    detector = EnsembleAnomalyDetector()
    metrics  = Metrics()
    anomaly_log: List[Dict] = []

    console = Console() if RICH_AVAILABLE else None
    print(f"\nStarting anomaly detection stream for {duration}s @ {rate}Hz ...\n")

    async for ts, x, true_label in stream.stream(duration):
        event = detector.detect(x, ts, true_label)
        metrics.update(event)

        if event.ensemble_vote:
            dt_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
            feat_str = ", ".join(f"{v:.2f}" for v in event.features)
            marker = "✓TP" if true_label else "✗FP"
            msg = f"[{dt_str}] ANOMALY [{marker}] | iso_score={event.iso_score:.3f} | features=[{feat_str}]"
            if console:
                console.print(msg, style="bold red" if true_label else "yellow")
            else:
                print(msg)

            anomaly_log.append({
                "timestamp":   ts,
                "iso_score":   round(event.iso_score, 4),
                "z_score":     event.z_score,
                "ewma":        event.ewma,
                "iso_forest":  event.iso_forest,
                "true_label":  event.true_label,
                **{f"feat_{i}": round(float(v), 4) for i, v in enumerate(event.features)},
            })

    # ── Final summary ──────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print(f"  Samples processed : {metrics.total}")
    print(f"  Anomalies detected: {metrics.detected}")
    print(f"  Precision         : {metrics.precision:.4f}")
    print(f"  Recall            : {metrics.recall:.4f}")
    print(f"  F1 Score          : {metrics.f1:.4f}")

    if anomaly_log:
        df = pd.DataFrame(anomaly_log)
        df.to_csv(output_csv, index=False)
        print(f"\nAnomaly log saved to: {output_csv}")
    else:
        print("\nNo anomalies detected during the run.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real-time anomaly detector")
    parser.add_argument("--duration", type=float, default=30.0, help="Run duration in seconds")
    parser.add_argument("--rate",     type=float, default=10.0,  help="Sample rate (Hz)")
    parser.add_argument("--output",   type=str,   default="anomaly_log.csv", help="Output CSV path")
    args = parser.parse_args()

    asyncio.run(run_detector(args.duration, args.rate, args.output))
