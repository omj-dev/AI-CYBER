import json
import random
from datetime import datetime, timedelta

def generate_logs():
    events = []
    base_time = datetime(2026, 9, 1, 9, 0, 0)
    normal_users = ["alice", "bob", "carol", "dave"]
    normal_ips = ["10.0.0.5", "10.0.0.12", "10.0.0.23", "10.0.0.31"]

   
    for i in range(150):
        events.append({
            "timestamp": (base_time + timedelta(minutes=i*2)).isoformat(),
            "source_ip": random.choice(normal_ips),
            "user": random.choice(normal_users),
            "event_type": "login_success"
        })

    attacker_ip = "203.0.113.77"
    attack_time = base_time + timedelta(hours=2)
    for i in range(6):
        events.append({
            "timestamp": (attack_time + timedelta(seconds=i*20)).isoformat(),
            "source_ip": attacker_ip,
            "user": "admin",
            "event_type": "login_failed"
        })
    events.append({
        "timestamp": (attack_time + timedelta(seconds=150)).isoformat(),
        "source_ip": attacker_ip,
        "user": "admin",
        "event_type": "login_success"
    })

    events.append({
        "timestamp": (base_time + timedelta(hours=4)).isoformat(),
        "source_ip": "45.33.10.20",  
        "user": "carol",
        "event_type": "login_success"
    })
    events.append({
        "timestamp": (base_time + timedelta(hours=4, minutes=3)).isoformat(),
        "source_ip": "198.51.100.9",
        "user": "carol",
        "event_type": "login_success"
    })

    events.append({
        "timestamp": (base_time.replace(hour=3, minute=15)).isoformat(),
        "source_ip": "10.0.0.99",
        "user": "bob",
        "event_type": "login_success"
    })

    random.shuffle(events)
    return events

if __name__ == "__main__":
    logs = generate_logs()
    with open("raw_logs.json", "w") as f:
        json.dump(logs, f, indent=2)
    print(f"Generated {len(logs)} log events -> raw_logs.json")