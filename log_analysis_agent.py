from datetime import datetime, timedelta
from collections import defaultdict

def parse_ts(ts):
    return datetime.fromisoformat(ts)

def detect_brute_force(events, threshold=5, window_minutes=5):
    flagged = []
    by_ip_user = defaultdict(list)
    for e in events:
        if e["event_type"] == "login_failed":
            by_ip_user[(e["source_ip"], e["user"])].append(e)

    for (ip, user), fails in by_ip_user.items():
        fails.sort(key=lambda e: e["timestamp"])
        for i in range(len(fails) - threshold + 1):
            window = fails[i:i+threshold]
            t0 = parse_ts(window[0]["timestamp"])
            t1 = parse_ts(window[-1]["timestamp"])
            if (t1 - t0) <= timedelta(minutes=window_minutes):
                flagged.append({**window[-1], "flag": "brute_force_suspected"})
                break
    return flagged

def detect_impossible_travel(events, max_minutes=10):
    flagged = []
    by_user = defaultdict(list)
    for e in events:
        if e["event_type"] == "login_success":
            by_user[e["user"]].append(e)

    for user, logins in by_user.items():
        logins.sort(key=lambda e: e["timestamp"])
        for i in range(len(logins) - 1):
            t0 = parse_ts(logins[i]["timestamp"])
            t1 = parse_ts(logins[i+1]["timestamp"])
            if logins[i]["source_ip"] != logins[i+1]["source_ip"] and (t1 - t0) <= timedelta(minutes=max_minutes):
                flagged.append({**logins[i+1], "flag": "impossible_travel_suspected"})
    return flagged

def detect_off_hours(events, start_hour=0, end_hour=5):
    flagged = []
    for e in events:
        if e["event_type"] == "login_success":
            hour = parse_ts(e["timestamp"]).hour
            if start_hour <= hour < end_hour:
                flagged.append({**e, "flag": "off_hours_access_suspected"})
    return flagged

def analyze_logs(all_events):
    flagged = []
    flagged += detect_brute_force(all_events)
    flagged += detect_impossible_travel(all_events)
    flagged += detect_off_hours(all_events)
    return flagged