
import pandas as pd

from detector import detect_s3_destructive_bursts


def make_event(time, event_name, bucket):
    return {
        "time": pd.Timestamp(time, tz="UTC"),
        "eventName": event_name,
        "user": "test-user",
        "sourceIP": "192.0.2.10",
        "errorCode": None,
        "requestParameters": f'{{"bucketName": "{bucket}"}}',
    }


# Benign control: uploads and deletions in one bucket.
df = pd.DataFrame([
    make_event("2026-01-01 10:00:00", "PutObject", "test-bucket"),
    make_event("2026-01-01 10:00:10", "DeleteObject", "test-bucket"),
    make_event("2026-01-01 10:00:20", "DeleteObject", "test-bucket"),
    make_event("2026-01-01 10:00:30", "DeleteBucket", "test-bucket"),
])

alerts, evidence = detect_s3_destructive_bursts(df)

print("Benign test alerts:", len(alerts))
print("Expected alerts: 0")

assert alerts.empty, "FAIL: one-bucket activity unexpectedly triggered an alert."
print("PASS: one-bucket activity did not trigger an alert.")

# Positive control: upload, then destructive operations across two buckets.
positive_df = pd.DataFrame([
    make_event("2026-01-01 11:00:00", "PutObject", "bucket-a"),
    make_event("2026-01-01 11:00:10", "DeleteObject", "bucket-a"),
    make_event("2026-01-01 11:00:20", "DeleteObject", "bucket-b"),
    make_event("2026-01-01 11:00:30", "DeleteBucket", "bucket-b"),
])

positive_alerts, positive_evidence = detect_s3_destructive_bursts(
    positive_df
)

print("Positive test alerts:", len(positive_alerts))
print("Expected alerts: 1")

assert len(positive_alerts) == 1, (
    "FAIL: qualifying multi-bucket activity did not trigger an alert."
)
print("PASS: qualifying multi-bucket activity triggered an alert.")
# Failed-operation test: the failed deletion must not count
failed_df = pd.DataFrame([
    make_event("2026-01-01 12:00:00", "PutObject", "bucket-a"),
    make_event("2026-01-01 12:00:10", "DeleteObject", "bucket-a"),
    make_event("2026-01-01 12:00:20", "DeleteObject", "bucket-b"),
    {
        **make_event(
            "2026-01-01 12:00:30",
            "DeleteBucket",
            "bucket-b",
        ),
        "errorCode": "AccessDenied",
        "is_failure": True,
    },
])

failed_alerts, failed_evidence = detect_s3_destructive_bursts(
    failed_df
)

print("Failed-operation test alerts:", len(failed_alerts))
print("Expected alerts: 0")

assert failed_alerts.empty, (
    "FAIL: a failed destructive operation contributed to an alert."
)
print("PASS: failed destructive operation did not trigger an alert.")
# Rolling-window boundary tests

# Test 1: Qualifying activity within 15 minutes -> 1 alert
within_window_df = pd.DataFrame([
    make_event("2026-01-01 13:00:00", "PutObject", "bucket-a"),
    make_event("2026-01-01 13:05:00", "DeleteObject", "bucket-a"),
    make_event("2026-01-01 13:10:00", "DeleteObject", "bucket-b"),
    make_event("2026-01-01 13:14:59", "DeleteBucket", "bucket-b"),
])

within_alerts, _ = detect_s3_destructive_bursts(within_window_df)

print("Within-window test alerts:", len(within_alerts))
print("Expected alerts: 1")

assert len(within_alerts) == 1, (
    "FAIL: qualifying activity within 15 minutes did not trigger."
)
print("PASS: qualifying activity within 15 minutes triggered an alert.")


# Test 2: Destructive activity spans more than 15 minutes -> 0 alerts
outside_window_df = pd.DataFrame([
    make_event("2026-01-01 14:00:00", "PutObject", "bucket-a"),
    make_event("2026-01-01 14:01:00", "DeleteObject", "bucket-a"),
    make_event("2026-01-01 14:08:00", "DeleteObject", "bucket-b"),
    make_event("2026-01-01 14:16:01", "DeleteBucket", "bucket-b"),
])

outside_alerts, _ = detect_s3_destructive_bursts(outside_window_df)

print("Outside-window test alerts:", len(outside_alerts))
print("Expected alerts: 0")

assert outside_alerts.empty, (
    "FAIL: events spanning more than 15 minutes triggered an alert."
)
print("PASS: events spanning more than 15 minutes did not trigger an alert.")
# Incident-separation tests

# Test 6: Two qualifying bursts separated by 4 minutes -> 1 incident
short_gap_df = pd.DataFrame([
    make_event("2026-01-01 15:00:00", "PutObject", "bucket-a"),
    make_event("2026-01-01 15:00:10", "DeleteObject", "bucket-a"),
    make_event("2026-01-01 15:00:20", "DeleteObject", "bucket-b"),
    make_event("2026-01-01 15:00:30", "DeleteBucket", "bucket-b"),

    make_event("2026-01-01 15:04:30", "PutObject", "bucket-c"),
    make_event("2026-01-01 15:04:40", "DeleteObject", "bucket-c"),
    make_event("2026-01-01 15:04:50", "DeleteObject", "bucket-d"),
    make_event("2026-01-01 15:05:00", "DeleteBucket", "bucket-d"),
])

short_gap_alerts, _ = detect_s3_destructive_bursts(short_gap_df)

print("Short-gap test alerts:", len(short_gap_alerts))
print("Expected alerts: 1")

assert len(short_gap_alerts) == 1, (
    "FAIL: bursts separated by a short gap were not merged."
)
print("PASS: bursts separated by a short gap were merged.")


# Test 7: Two qualifying bursts separated by 6 minutes -> 2 incidents
long_gap_df = pd.DataFrame([
    make_event("2026-01-01 16:00:00", "PutObject", "bucket-a"),
    make_event("2026-01-01 16:00:10", "DeleteObject", "bucket-a"),
    make_event("2026-01-01 16:00:20", "DeleteObject", "bucket-b"),
    make_event("2026-01-01 16:00:30", "DeleteBucket", "bucket-b"),

    make_event("2026-01-01 16:06:30", "PutObject", "bucket-c"),
    make_event("2026-01-01 16:06:40", "DeleteObject", "bucket-c"),
    make_event("2026-01-01 16:06:50", "DeleteObject", "bucket-d"),
    make_event("2026-01-01 16:07:00", "DeleteBucket", "bucket-d"),
])

long_gap_alerts, _ = detect_s3_destructive_bursts(long_gap_df)

print("Long-gap test alerts:", len(long_gap_alerts))
print("Expected alerts: 2")

assert len(long_gap_alerts) == 2, (
    "FAIL: bursts separated by a long gap were not split."
)
print("PASS: bursts separated by a long gap were split.")