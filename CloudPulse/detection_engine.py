
"""
CloudPulse statistical detection engine.

Responsibilities:
- Load and validate CloudTrail-style CSV events.
- Normalize timestamps, event names, and failure indicators.
- Build fixed-frequency event-count and failure-count signals.
- Detect statistical anomalies using a historical rolling median/MAD baseline.
- Consolidate anomaly buckets into windows.
- Associate original events with anomaly windows.
- Optionally persist results as CSV files.

Important:
Statistical anomalies are not proof of malicious activity.
Security-rule evaluation belongs in rules.py.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


# ============================================================
# DEFAULT CONFIGURATION
# ============================================================

FREQ = "5min"
BASELINE_WINDOW = 48
ANOMALY_THRESHOLD = 4.0
GAP_THRESHOLD_HOURS = 24

# A floor of 1 prevents division by zero and excessively large
# scores for zero-MAD baselines. It is expressed in event counts.
MAD_SCALE_FLOOR = 1.0

OUTPUT_DIR = Path("logged")

EMPTY_VALUES = {
    "",
    "none",
    "null",
    "nan",
    "nat",
    "n/a",
    "na",
}


# ============================================================
# COLUMN AND VALUE HELPERS
# ============================================================

def find_column(
    df: pd.DataFrame,
    candidates: list[str],
) -> str | None:
    """Find a column by name without case sensitivity."""

    columns = {
        str(column).strip().lower(): column
        for column in df.columns
    }

    for candidate in candidates:
        match = columns.get(candidate.strip().lower())

        if match is not None:
            return match

    return None


def is_present(value: Any) -> bool:
    """Return False for common empty/null representations."""

    if value is None or pd.isna(value):
        return False

    return str(value).strip().lower() not in EMPTY_VALUES


def parse_boolean(value: Any) -> bool:
    """Interpret common CSV representations of a true value."""

    if isinstance(value, (bool, np.bool_)):
        return bool(value)

    if isinstance(value, (int, np.integer)):
        return value == 1

    if isinstance(value, (float, np.floating)):
        return np.isfinite(value) and value == 1

    return str(value).strip().lower() in {
        "true",
        "1",
        "yes",
        "y",
    }


def empty_frame(columns: list[str]) -> pd.DataFrame:
    """Create an empty DataFrame with a predictable schema."""

    return pd.DataFrame(columns=columns)


# ============================================================
# 1. LOAD AND NORMALIZE EVENTS
# ============================================================

def load_events(
    csv_path: str | Path,
) -> tuple[pd.DataFrame, int]:
    """
    Load a CSV and normalize the fields used by detection.

    Returns:
        (normalized_events, invalid_timestamp_count)

    Duplicate event IDs are reported in the normalized data
    quality metadata but are not automatically removed.
    """

    csv_path = Path(csv_path)

    if not csv_path.is_file():
        raise FileNotFoundError(
            f"Input CSV not found: {csv_path}"
        )

    df = pd.read_csv(
        csv_path,
        dtype=str,
        keep_default_na=False,
        low_memory=False,
    )

    if df.empty:
        raise ValueError(
            "The input CSV contains no events."
        )

    if not df.columns.is_unique:
        raise ValueError(
            "The input CSV contains duplicate column names."
        )

    time_col = find_column(
        df,
        ["time", "eventTime", "event_time", "timestamp"],
    )

    event_col = find_column(
        df,
        ["eventName", "event_name"],
    )

    if time_col is None:
        raise ValueError(
            "No event timestamp column found. "
            "Expected time, eventTime, event_time, or timestamp."
        )

    if event_col is None:
        raise ValueError(
            "No eventName column found."
        )

    # Parse all timestamps as UTC to avoid mixed timezone issues.
    df["time"] = pd.to_datetime(
        df[time_col],
        utc=True,
        errors="coerce",
    )

    invalid_timestamps = int(df["time"].isna().sum())

    # Events without valid timestamps cannot be placed in buckets.
    df = df.loc[df["time"].notna()].copy()

    if df.empty:
        raise ValueError(
            "No events have valid timestamps."
        )

    df["eventName"] = (
        df[event_col]
        .astype(str)
        .str.strip()
    )

    empty_event_names = df["eventName"].map(
        lambda value: not is_present(value)
    )

    if empty_event_names.any():
        raise ValueError(
            f"{int(empty_event_names.sum())} event(s) have "
            "missing event names. Correct these rows before analysis."
        )

    # Normalize common variants of event IDs.
    event_id_col = find_column(
        df,
        ["eventID", "eventId", "event_id"],
    )

    if event_id_col is not None:
        df["eventID"] = df[event_id_col].astype(str).str.strip()

        df.loc[
            df["eventID"].map(
                lambda value: not is_present(value)
            ),
            "eventID",
        ] = ""
    else:
        df["eventID"] = ""

    # Determine whether an event represents a failure.
    failure_col = find_column(
        df,
        ["is_failure", "isFailure", "failed"],
    )

    error_col = find_column(
        df,
        ["errorCode", "error_code"],
    )

    message_col = find_column(
        df,
        ["errorMessage", "error_message"],
    )

    failures = pd.Series(
        False,
        index=df.index,
        dtype=bool,
    )

    if failure_col is not None:
        failures |= df[failure_col].map(parse_boolean)

    if error_col is not None:
        failures |= df[error_col].map(is_present)

    if message_col is not None:
        failures |= df[message_col].map(is_present)

    df["is_failure"] = failures.astype(bool)

    # Sort chronologically. Stable sorting preserves the input
    # order when two events have identical timestamps.
    df = (
        df.sort_values("time", kind="stable")
        .reset_index(drop=True)
    )

    df["event_row"] = np.arange(
        len(df),
        dtype=np.int64,
    )

    # Count duplicate, non-empty event IDs without dropping rows.
    valid_ids = df.loc[
        df["eventID"].ne(""),
        "eventID",
    ]

    duplicate_event_ids = int(
        valid_ids.duplicated(keep=False).sum()
    )

    # Segment events separated by long collection gaps.
    time_difference = df["time"].diff()

    df["segment_id"] = (
        time_difference.gt(
            pd.Timedelta(hours=GAP_THRESHOLD_HOURS)
        )
        .cumsum()
        .astype(int)
    )

    # Data-quality details are returned separately in analysis
    # metadata so the event schema remains usable by rules.py.
    df.attrs["data_quality"] = {
        "input_rows": int(len(pd.read_csv(
            csv_path,
            usecols=[time_col],
            low_memory=False,
        ))),
        "valid_timestamp_rows": int(len(df)),
        "invalid_timestamps": invalid_timestamps,
        "duplicate_event_id_rows": duplicate_event_ids,
        "empty_event_names": 0,
    }

    return df, invalid_timestamps


# ============================================================
# 2. BUILD TIME SIGNALS
# ============================================================

def build_signals(
    events: pd.DataFrame,
    freq: str = FREQ,
) -> pd.DataFrame:
    """
    Build event-count and failure-count time series.

    Segments are processed separately to prevent long periods
    without collected logs from creating artificial zero buckets.
    """

    required = {
        "time",
        "eventName",
        "is_failure",
        "segment_id",
    }

    missing = required.difference(events.columns)

    if missing:
        raise ValueError(
            "Cannot build signals. Missing columns: "
            + ", ".join(sorted(missing))
        )

    if events.empty:
        raise ValueError(
            "Cannot build signals from an empty event DataFrame."
        )

    if not pd.api.types.is_datetime64_any_dtype(events["time"]):
        raise TypeError(
            "events['time'] must contain parsed datetime values."
        )

    if events["time"].isna().any():
        raise ValueError(
            "events['time'] contains invalid timestamps."
        )

    if not isinstance(freq, str) or not freq.strip():
        raise ValueError("freq must be a non-empty frequency string.")

    segments = []

    for segment_id, group in events.groupby(
        "segment_id",
        sort=True,
    ):
        indexed = group.set_index("time").sort_index()

        # Resample each segment independently.
        signals = indexed.resample(freq).agg(
            total=("eventName", "count"),
            failed=("is_failure", "sum"),
        )

        full_index = pd.date_range(
            start=indexed.index.min().floor(freq),
            end=indexed.index.max().floor(freq),
            freq=freq,
        )

        signals = signals.reindex(
            full_index,
            fill_value=0,
        )

        signals.index.name = "time"
        signals["segment_id"] = int(segment_id)

        segments.append(signals)

    if not segments:
        raise ValueError(
            "No time signals could be generated."
        )

    result = pd.concat(segments).sort_index()

    result["total"] = result["total"].astype("int64")
    result["failed"] = result["failed"].astype("int64")

    return result


# ============================================================
# 3. DETECT ANOMALOUS WINDOWS
# ============================================================

ANOMALY_COLUMNS = [
    "window_id",
    "segment_id",
    "signal",
    "direction",
    "start",
    "end",
    "peak_time",
    "peak_count",
    "baseline_median",
    "z_peak",
    "mass",
    "flagged_bins",
]


def detect_segment_anomalies(
    signals: pd.DataFrame,
    signal_name: str,
    segment_id: int,
    baseline_window: int = BASELINE_WINDOW,
    anomaly_threshold: float = ANOMALY_THRESHOLD,
    mad_scale_floor: float = MAD_SCALE_FLOOR,
    merge_gap_bins: int = 0,
) -> pd.DataFrame:
    """
    Detect unusual buckets against a strictly historical
    rolling median/MAD baseline.

    merge_gap_bins=0 preserves the original behavior: only
    directly adjacent anomalous buckets are grouped together.

    Positive z-scores represent spikes; negative scores represent
    drops. Both are reported, but neither proves malicious intent.
    """

    if signal_name not in signals.columns:
        raise ValueError(
            f"Signal '{signal_name}' does not exist."
        )

    if baseline_window < 2:
        raise ValueError(
            "baseline_window must be at least 2."
        )

    if not np.isfinite(anomaly_threshold) or anomaly_threshold <= 0:
        raise ValueError(
            "anomaly_threshold must be a finite positive number."
        )

    if not np.isfinite(mad_scale_floor) or mad_scale_floor <= 0:
        raise ValueError(
            "mad_scale_floor must be a finite positive number."
        )

    if merge_gap_bins < 0:
        raise ValueError(
            "merge_gap_bins cannot be negative."
        )

    values = pd.to_numeric(
        signals[signal_name],
        errors="coerce",
    ).astype(float)

    if values.isna().any() or not np.isfinite(values).all():
        raise ValueError(
            f"Signal '{signal_name}' contains invalid numeric values."
        )

    if (values < 0).any():
        raise ValueError(
            f"Signal '{signal_name}' cannot contain negative counts."
        )

    # Exclude the current bucket to avoid baseline contamination.
    history = values.shift(1)

    rolling_median = history.rolling(
        window=baseline_window,
        min_periods=baseline_window,
    ).median()

    rolling_mad = history.rolling(
        window=baseline_window,
        min_periods=baseline_window,
    ).apply(
        lambda window: np.median(
            np.abs(window - np.median(window))
        ),
        raw=True,
    )

    # 1.4826 * MAD estimates standard deviation under a normal
    # distribution. The floor handles zero or very small MAD.
    scale = (1.4826 * rolling_mad).clip(
        lower=mad_scale_floor,
    )

    z_score = (values - rolling_median) / scale

    # Two-sided detection: unusually high OR low event counts.
    anomaly_mask = (
        rolling_median.notna()
        & z_score.abs().gt(anomaly_threshold)
    )

    anomaly_positions = np.flatnonzero(
        anomaly_mask.to_numpy()
    )

    if len(anomaly_positions) == 0:
        return empty_frame(ANOMALY_COLUMNS)

    # Group adjacent anomalous buckets. Optionally bridge a small
    # number of normal buckets, while retaining their actual count.
    groups: list[list[int]] = []
    current_group = [int(anomaly_positions[0])]

    for position in anomaly_positions[1:]:
        position = int(position)

        gap_bins = position - current_group[-1] - 1

        if gap_bins <= merge_gap_bins:
            current_group.append(position)
        else:
            groups.append(current_group)
            current_group = [position]

    groups.append(current_group)

    records = []

    for positions in groups:
        actual_times = values.index[positions]

        # The peak is the anomalous bucket with the largest
        # absolute score, not necessarily the largest raw count.
        peak_position = max(
            positions,
            key=lambda pos: abs(float(z_score.iloc[pos])),
        )

        peak_time = values.index[peak_position]
        peak_score = float(z_score.iloc[peak_position])

        records.append({
            "window_id": "",
            "segment_id": int(segment_id),
            "signal": signal_name,
            "direction": (
                "spike" if peak_score > 0 else "drop"
            ),
            "start": actual_times.min(),
            "end": actual_times.max(),
            "peak_time": peak_time,
            "peak_count": int(values.iloc[peak_position]),
            "baseline_median": round(
                float(rolling_median.iloc[peak_position]),
                3,
            ),
            "z_peak": round(peak_score, 3),
            "mass": int(values.iloc[positions].sum()),
            "flagged_bins": len(positions),
        })

    return pd.DataFrame(
        records,
        columns=ANOMALY_COLUMNS,
    )


def detect_anomalies(
    signals: pd.DataFrame,
    baseline_window: int = BASELINE_WINDOW,
    anomaly_threshold: float = ANOMALY_THRESHOLD,
    mad_scale_floor: float = MAD_SCALE_FLOOR,
    merge_gap_bins: int = 0,
) -> pd.DataFrame:
    """Detect anomalies in event and failure counts."""

    detected = []

    if signals.empty:
        return empty_frame(ANOMALY_COLUMNS)

    if "segment_id" not in signals.columns:
        raise ValueError(
            "Signals must contain a segment_id column."
        )

    for segment_id, group in signals.groupby(
        "segment_id",
        sort=True,
    ):
        for signal_name in ("total", "failed"):
            result = detect_segment_anomalies(
                signals=group,
                signal_name=signal_name,
                segment_id=int(segment_id),
                baseline_window=baseline_window,
                anomaly_threshold=anomaly_threshold,
                mad_scale_floor=mad_scale_floor,
                merge_gap_bins=merge_gap_bins,
            )

            if not result.empty:
                detected.append(result)

    if not detected:
        return empty_frame(ANOMALY_COLUMNS)

    windows = pd.concat(
        detected,
        ignore_index=True,
    )

    windows = windows.sort_values(
        ["start", "signal", "segment_id"],
        kind="stable",
    ).reset_index(drop=True)

    windows["window_id"] = [
        f"ANOM-{number:04d}"
        for number in range(1, len(windows) + 1)
    ]

    return windows[ANOMALY_COLUMNS]


# ============================================================
# 4. ASSOCIATE EVENTS WITH ANOMALY WINDOWS
# ============================================================

SUSPICIOUS_EXTRA_COLUMNS = [
    "anomaly_window_ids",
    "anomaly_signals",
    "anomaly_peak_z",
    "detection_reason",
]


def log_suspicious_events(
    events: pd.DataFrame,
    windows: pd.DataFrame,
    freq: str = FREQ,
) -> pd.DataFrame:
    """
    Return original events that fall inside anomaly windows.

    Events are indexed by (segment_id, time bucket), avoiding
    a full event-table scan for every individual anomaly window.
    """

    result_columns = list(events.columns) + [
        column
        for column in SUSPICIOUS_EXTRA_COLUMNS
        if column not in events.columns
    ]

    if events.empty or windows.empty:
        result = events.iloc[0:0].copy()

        for column in SUSPICIOUS_EXTRA_COLUMNS:
            result[column] = pd.Series(dtype="object")

        return result[result_columns]

    required_window_columns = {
        "window_id",
        "segment_id",
        "signal",
        "start",
        "end",
        "z_peak",
    }

    missing = required_window_columns.difference(
        windows.columns
    )

    if missing:
        raise ValueError(
            "Anomaly windows are missing columns: "
            + ", ".join(sorted(missing))
        )

    # Assign each event to its five-minute (or configured)
    # bucket and construct a lookup for its segment and bucket.
    indexed_events = events.copy()

    indexed_events["_bucket"] = (
        indexed_events["time"].dt.floor(freq)
    )

    indexed_events["_event_index"] = np.arange(
        len(indexed_events),
        dtype=np.int64,
    )

    event_lookup: dict[tuple[int, pd.Timestamp], list[int]] = {}

    for row in indexed_events[
        ["segment_id", "_bucket", "_event_index"]
    ].itertuples(index=False, name=None):
        segment_id, bucket, event_index = row

        key = (int(segment_id), bucket)

        event_lookup.setdefault(key, []).append(
            int(event_index)
        )

    # Map each original event row to the windows explaining it.
    event_matches: dict[int, list[dict[str, Any]]] = {}

    for window in windows.itertuples(index=False):
        start = pd.Timestamp(window.start).floor(freq)
        end = pd.Timestamp(window.end).floor(freq)

        bucket_index = pd.date_range(
            start=start,
            end=end,
            freq=freq,
        )

        for bucket in bucket_index:
            matching_rows = event_lookup.get(
                (int(window.segment_id), bucket),
                [],
            )

            for event_index in matching_rows:
                event_matches.setdefault(
                    event_index,
                    [],
                ).append({
                    "window_id": str(window.window_id),
                    "signal": str(window.signal),
                    "z_peak": float(window.z_peak),
                })

    if not event_matches:
        result = events.iloc[0:0].copy()

        for column in SUSPICIOUS_EXTRA_COLUMNS:
            result[column] = pd.Series(dtype="object")

        return result[result_columns]

    matching_indices = sorted(event_matches)

    result = (
        indexed_events.iloc[matching_indices]
        .drop(columns=["_bucket", "_event_index"])
        .copy()
    )

    result["_match_index"] = matching_indices

    result["anomaly_window_ids"] = result[
        "_match_index"
    ].map(
        lambda index: "; ".join(sorted({
            match["window_id"]
            for match in event_matches[index]
        }))
    )

    result["anomaly_signals"] = result[
        "_match_index"
    ].map(
        lambda index: "; ".join(sorted({
            match["signal"]
            for match in event_matches[index]
        }))
    )

    result["anomaly_peak_z"] = result[
        "_match_index"
    ].map(
        lambda index: round(
            max(
                abs(match["z_peak"])
                for match in event_matches[index]
            ),
            3,
        )
    )

    result["detection_reason"] = (
        "Event occurred inside a statistically anomalous window."
    )

    result = (
        result.drop(columns=["_match_index"])
        .sort_values("time", kind="stable")
        .reset_index(drop=True)
    )

    return result[result_columns]


# ============================================================
# 5. ANALYZE EVENTS WITHOUT WRITING FILES
# ============================================================

def analyze_events(
    events: pd.DataFrame,
    baseline_window: int = BASELINE_WINDOW,
    anomaly_threshold: float = ANOMALY_THRESHOLD,
    freq: str = FREQ,
    mad_scale_floor: float = MAD_SCALE_FLOOR,
    merge_gap_bins: int = 0,
) -> dict[str, Any]:
    """
    Analyze an already-normalized event DataFrame.

    This function performs no file writes. It is suitable for
    Streamlit integration and repeatable unit tests.
    """

    signals = build_signals(
        events,
        freq=freq,
    )

    windows = detect_anomalies(
        signals,
        baseline_window=baseline_window,
        anomaly_threshold=anomaly_threshold,
        mad_scale_floor=mad_scale_floor,
        merge_gap_bins=merge_gap_bins,
    )

    suspicious = log_suspicious_events(
        events,
        windows,
        freq=freq,
    )

    return {
        "events": events,
        "signals": signals.reset_index(),
        "anomaly_windows": windows,
        "suspicious_events": suspicious,
        "metadata": {
            "event_count": int(len(events)),
            "signal_bucket_count": int(len(signals)),
            "anomaly_window_count": int(len(windows)),
            "suspicious_event_count": int(len(suspicious)),
            "frequency": freq,
            "baseline_window": int(baseline_window),
            "anomaly_threshold": float(anomaly_threshold),
            "mad_scale_floor": float(mad_scale_floor),
            "merge_gap_bins": int(merge_gap_bins),
        },
    }


# ============================================================
# 6. PERSIST RESULTS
# ============================================================

def run_detection_engine(
    csv_path: str | Path,
    output_dir: str | Path = OUTPUT_DIR,
    baseline_window: int | None = None,
    anomaly_threshold: float | None = None,
    freq: str = FREQ,
    mad_scale_floor: float = MAD_SCALE_FLOOR,
    merge_gap_bins: int = 0,
) -> dict[str, Any]:
    """
    Run detection on a CSV and save results for downstream tools.

    The existing call run_detection_engine(csv_path, output_dir)
    remains supported.
    """

    effective_baseline = (
        BASELINE_WINDOW
        if baseline_window is None
        else int(baseline_window)
    )

    effective_threshold = (
        ANOMALY_THRESHOLD
        if anomaly_threshold is None
        else float(anomaly_threshold)
    )

    if effective_baseline < 2:
        raise ValueError(
            "baseline_window must be at least 2."
        )

    if (
        not np.isfinite(effective_threshold)
        or effective_threshold <= 0
    ):
        raise ValueError(
            "anomaly_threshold must be a finite positive number."
        )

    events, invalid_timestamps = load_events(csv_path)

    # Capture metadata before analysis, as pandas attrs do not
    # reliably propagate through arbitrary DataFrame operations.
    data_quality = dict(
        events.attrs.get("data_quality", {})
    )

    result = analyze_events(
        events=events,
        baseline_window=effective_baseline,
        anomaly_threshold=effective_threshold,
        freq=freq,
        mad_scale_floor=mad_scale_floor,
        merge_gap_bins=merge_gap_bins,
    )

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    result["signals"].to_csv(
        output_path / "time_signals.csv",
        index=False,
    )

    result["anomaly_windows"].to_csv(
        output_path / "anomaly_windows.csv",
        index=False,
    )

    result["suspicious_events"].to_csv(
        output_path / "suspicious_events.csv",
        index=False,
    )

    metadata = {
        **result["metadata"],
        "invalid_timestamps_excluded": invalid_timestamps,
        "data_quality": data_quality,
    }

    result["metadata"] = metadata

    # A separate metadata file makes detection settings and
    # data-quality warnings available for audit and debugging.
    (output_path / "detection_metadata.json").write_text(
        json.dumps(metadata, indent=2, default=str),
        encoding="utf-8",
    )

    print("\nCLOUDPULSE DETECTION ENGINE")
    print("=" * 36)
    print(f"Events analyzed: {len(events):,}")
    print(
        "Invalid timestamps excluded: "
        f"{invalid_timestamps:,}"
    )
    print(
        "Duplicate event-ID rows: "
        f"{data_quality.get('duplicate_event_id_rows', 0):,}"
    )
    print(
        "Anomaly windows: "
        f"{len(result['anomaly_windows']):,}"
    )
    print(
        "Suspicious event rows: "
        f"{len(result['suspicious_events']):,}"
    )
    print(f"Output directory: {output_path.resolve()}")
    print(
        "\nStatistical anomalies are indicators for investigation, "
        "not confirmed attacks."
    )

    return result


# ============================================================
# 7. COMMAND-LINE ENTRY POINT
# ============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CloudPulse statistical detection engine"
    )

    parser.add_argument(
        "input_csv",
        help="Path to the normalized or compatible input CSV.",
    )

    parser.add_argument(
        "--output-dir",
        default=str(OUTPUT_DIR),
        help="Directory for detection output files.",
    )

    parser.add_argument(
        "--baseline-window",
        type=int,
        default=BASELINE_WINDOW,
        help="Number of previous buckets used for the baseline.",
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=ANOMALY_THRESHOLD,
        help="Absolute robust-score threshold for anomaly detection.",
    )

    parser.add_argument(
        "--frequency",
        default=FREQ,
        help="Pandas time frequency, for example 5min.",
    )

    parser.add_argument(
        "--merge-gap-bins",
        type=int,
        default=0,
        help="Number of normal buckets allowed between anomalies.",
    )

    args = parser.parse_args()

    run_detection_engine(
        csv_path=args.input_csv,
        output_dir=args.output_dir,
        baseline_window=args.baseline_window,
        anomaly_threshold=args.threshold,
        freq=args.frequency,
        merge_gap_bins=args.merge_gap_bins,
    )
