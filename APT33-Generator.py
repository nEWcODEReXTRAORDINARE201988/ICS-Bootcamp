import json
import random
from datetime import datetime, timedelta

# Configuration
num_logs_per_day = 1000
output_day1 = "apt33_ics_day1.json"
output_day2 = "apt33_ics_day2.json"

# Time ranges
start_time_day1 = datetime(2025, 7, 29, 0, 0, 0)
start_time_day2 = datetime(2025, 7, 30, 0, 0, 0)

# IP Definitions (from docker-compose.yml)
attacker_ip = "192.168.3.30"
c2_ips = ["8.8.8.8", "203.0.113.50", "104.16.249.249"]
internal_master = "192.168.1.100"
internal_outstations = [f"192.168.1.{i}" for i in range(110, 120)]
internal_ics_hosts = internal_outstations + [internal_master]
internal_it_hosts = [f"192.168.2.{i}" for i in range(10, 20)]
external_clients = [f"198.51.100.{i}" for i in range(10, 50)]

# Function codes, URIs, etc.
modbus_funcs = [1, 3, 5, 6, 15, 16]
dnp3_funcs = [0, 1, 2, 129, 130]
http_uris = ["/update", "/status", "/config", "/beacon"]
http_agents = ["Mozilla/5.0", "curl/7.68.0", "Python-urllib/3.9"]
dns_queries = ["plc.internal", "update.win", "ntp.org", "malicious.biz"]
dns_types = ["A", "AAAA", "TXT", "MX"]

def random_time(base_time, seconds_range=86400):
    return base_time + timedelta(seconds=random.randint(0, seconds_range - 1))

def make_entry(ts, src, dst, log_type, extra):
    base = {
        "@timestamp": ts.isoformat(),
        "id.orig_h": src,
        "id.resp_h": dst,
        "log_type": log_type
    }
    base.update(extra)
    return base

def generate_logs(day_start, outfile, is_attack_day=False):
    data = []
    for _ in range(num_logs_per_day):
        ts = random_time(day_start)

        is_attacker = random.random() < (0.05 if is_attack_day else 0.01)
        log_type = random.choices(
            ["modbus.log", "dnp3.log", "http.log", "dns.log", "rdp.log", "conn.log"],
            weights=[0.2, 0.15, 0.2, 0.2, 0.1, 0.15]
        )[0]

        # Build log entry
        if log_type == "modbus.log":
            src = attacker_ip if is_attacker else internal_master
            dst = random.choice(internal_outstations)
            entry = make_entry(ts, src, dst, log_type, {
                "modbus.func_code": random.choice(modbus_funcs),
                "modbus.exception_code": random.choice([None, 1, 2]),
                "tags": ["apt33"] if is_attacker else []
            })

        elif log_type == "dnp3.log":
            src = attacker_ip if is_attacker else internal_master
            dst = random.choice(internal_outstations)
            entry = make_entry(ts, src, dst, log_type, {
                "dnp3.function_code": random.choice(dnp3_funcs),
                "dnp3.iin": random.randint(0, 1),
                "tags": ["apt33"] if is_attacker else []
            })

        elif log_type == "http.log":
            if is_attacker and random.random() < 0.5:
                src = attacker_ip
                dst = random.choice(c2_ips)
            else:
                src = random.choice(external_clients + internal_it_hosts)
                dst = random.choice(internal_it_hosts)
            entry = make_entry(ts, src, dst, log_type, {
                "http.method": "GET",
                "http.uri": random.choice(http_uris),
                "http.user_agent": random.choice(http_agents),
                "http.referer": "http://example.com",
                "tags": ["apt33"] if src == attacker_ip else []
            })

        elif log_type == "dns.log":
            if is_attacker and random.random() < 0.5:
                src = attacker_ip
                dst = random.choice(c2_ips)
            else:
                src = random.choice(external_clients + internal_it_hosts)
                dst = random.choice(["8.8.8.8", "1.1.1.1"])
            entry = make_entry(ts, src, dst, log_type, {
                "dns.query": random.choice(dns_queries),
                "dns.qtype_name": random.choice(dns_types),
                "dns.ttl": random.randint(30, 600),
                "tags": ["apt33"] if src == attacker_ip else []
            })

        elif log_type == "rdp.log":
            src = attacker_ip if is_attacker else random.choice(internal_it_hosts)
            dst = random.choice(internal_it_hosts)
            entry = make_entry(ts, src, dst, log_type, {
                "id.resp_p": random.choice([3389, 3390]),
                "tags": ["apt33"] if src == attacker_ip else []
            })

        elif log_type == "conn.log":
            src = attacker_ip if is_attacker else random.choice(external_clients + internal_it_hosts)
            dst = random.choice(internal_ics_hosts + internal_it_hosts)
            entry = make_entry(ts, src, dst, log_type, {
                "proto": random.choice(["tcp", "udp"]),
                "id.resp_p": random.choice([22, 80, 443, 502, 20000, 3389, 8080]),
                "tags": ["apt33"] if src == attacker_ip else []
            })

        data.append(entry)

    # Write to file
    with open(outfile, "w") as f:
        for d in data:
            json.dump(d, f)
            f.write("\n")

    print(f"✅ Generated {len(data)} logs for {outfile}")

# Generate Day 1 and Day 2
generate_logs(start_time_day1, output_day1, is_attack_day=False)
generate_logs(start_time_day2, output_day2, is_attack_day=True)
