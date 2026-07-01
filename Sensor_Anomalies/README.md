# Real-Time Anomaly Detector

Streams synthetic sensor/telemetry data and flags anomalies as they come in — no batch processing, no waiting until the end. Built around Python's asyncio so the detection loop stays non-blocking at whatever sample rate you throw at it.

## How it works

Three detectors run in parallel on every incoming sample and majority-vote on the result. Two out of three have to agree before something gets flagged.

**Z-Score** tracks an exponential moving mean and variance per channel and fires when any channel drifts more than 3.5 standard deviations. Updates online so it adapts to slow drift over time.

**EWMA Control Chart** applies exponentially weighted smoothing and computes control limits using the standard EWMA variance formula. Good at catching gradual shifts that Z-score misses because they look normal sample-by-sample.

**Isolation Forest** retrains every 50 samples on a 300-sample sliding window. More expensive but picks up collective anomalies — cases where no single channel looks weird but the combination is unusual.

The synthetic stream injects three anomaly types at random: single-channel spikes, single-channel drops, and collective shifts across all channels. Slow concept drift runs the whole time so the detectors have to keep up.

## Setup

```bash
pip install numpy pandas scikit-learn rich
```

`rich` is optional — if it's not installed the detector falls back to plain print output.

## Run it

```bash
python 03_realtime_anomaly_detector.py --duration 60 --rate 10
```

Default is 30 seconds at 10 Hz. Bump `--rate` to stress-test the async loop. Anomaly events get written to `anomaly_log.csv` at the end.

## Options

| Flag | Default | What it does |
|------|---------|--------------|
| `--duration` | 30 | How long to run in seconds |
| `--rate` | 10 | Sample rate in Hz |
| `--output` | anomaly_log.csv | Where to save the anomaly log |

## Output

Console prints each detected anomaly in real time with timestamp, ISO score, and raw feature values. TP/FP labels are included since the simulator knows ground truth.

Final summary at the end:

```
Samples processed : 600
Anomalies detected: 21
Precision         : 0.7143
Recall            : 0.8333
F1 Score          : 0.7692
```

CSV log includes timestamp, all three detector votes, ISO score, true label, and all feature values per event.

## Notes

The Isolation Forest waits for 50 samples before it starts predicting — cold start is unavoidable with tree-based models. Z-score and EWMA are online from sample one.

Retraining every 50 samples is intentional. Longer intervals miss concept drift; shorter intervals make the contamination estimate unstable on small windows.
