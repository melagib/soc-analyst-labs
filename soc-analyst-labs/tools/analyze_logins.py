"""Summarize synthetic CSV authentication logs; Python standard library only."""

import argparse
import csv
from collections import Counter, defaultdict
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path


def load_events(path):
    """Reject malformed data rather than silently dropping evidence."""
    events = []
    with Path(path).open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != ["timestamp", "user", "source_ip", "event"]:
            raise ValueError("Expected header: timestamp,user,source_ip,event")
        for row in reader:
            line = reader.line_num
            if None in row or any(value is None or not value.strip() for value in row.values()):
                raise ValueError("Line {}: missing or extra fields".format(line))
            row = {key: value.strip() for key, value in row.items()}
            try:
                # This exercise uses UTC timestamps with a required trailing Z.
                timestamp = datetime.strptime(row["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
                row["source_ip"] = str(ip_address(row["source_ip"]))
            except ValueError as error:
                raise ValueError("Line {}: invalid UTC timestamp or IP address".format(line)) from error
            if row["event"] not in ("success", "failure"):
                raise ValueError("Line {}: event must be success or failure".format(line))
            row["time"] = timestamp
            events.append(row)
    return sorted(events, key=lambda event: event["time"])


def summarize(events, threshold=5):
    """Count failures across the entire file, not within a rolling window."""
    if threshold < 1:
        raise ValueError("Threshold must be at least 1")
    failures = Counter()
    users = defaultdict(set)
    pair_failures = Counter()
    followups = []
    # Evaluate successes before failures at the same time: 'later' is strict.
    ordered = sorted(events, key=lambda event: (event["time"], event["event"] == "failure"))
    for event in ordered:
        ip = event["source_ip"]
        pair = (ip, event["user"])
        if event["event"] == "failure":
            failures[ip] += 1
            users[ip].add(event["user"])
            pair_failures[pair] += 1
        else:
            prior = pair_failures[pair]
            if prior >= threshold:
                followups.append((event["timestamp"], ip, event["user"], prior))
            # Start a new sequence after any successful login for this pair.
            pair_failures[pair] = 0

    lines = [
        "SYNTHETIC LOGIN INVESTIGATION",
        "Events: {}".format(len(events)),
        "Failures: {}".format(sum(failures.values())),
        "Successes: {}".format(sum(event["event"] == "success" for event in events)),
        "Failure threshold: {} (counts across the whole file)".format(threshold),
        "", "Failure counts by source IP:",
    ]
    for ip, count in sorted(failures.items(), key=lambda item: (-item[1], item[0])):
        flag = " [REVIEW]" if count >= threshold else ""
        lines.append("  {}: {} failures; users={}{}".format(ip, count, ",".join(sorted(users[ip])), flag))
    if not failures:
        lines.append("  None")
    lines.extend(["", "Success after repeated failures for the same IP and user:"])
    for timestamp, ip, user, count in followups:
        lines.append("  {} | {} | {} | {} prior failures".format(timestamp, ip, user, count))
    if not followups:
        lines.append("  None")
    lines.extend(["", "Review flags are leads, not proof of an attack or compromise."])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_file", type=Path)
    parser.add_argument("--threshold", type=int, default=5)
    args = parser.parse_args()
    try:
        print(summarize(load_events(args.csv_file), args.threshold))
    except (OSError, UnicodeError, ValueError, csv.Error) as error:
        parser.exit(2, "Error: {}\n".format(error))


if __name__ == "__main__":
    main()
