#!/usr/bin/env python3

import argparse
from collections import defaultdict
from datetime import datetime

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    END = '\033[0m'

# 🔥 FIXED PARSER (works for Apache/XAMPP logs)
def parse_log_entry(line):
    try:
        parts = line.split('"')

        if len(parts) < 3:
            return None

        # First part → IP + timestamp
        first = parts[0].split()
        ip = first[0]
        timestamp = first[3].strip('[]')

        # Second part → request
        request = parts[1].split()
        method = request[0]
        url = request[1]
        http_version = request[2]

        # Third part → status + size
        rest = parts[2].split()
        status = int(rest[0])
        size = rest[1] if len(rest) > 1 else '0'

        return {
            'ip': ip,
            'timestamp': timestamp,
            'method': method,
            'url': url,
            'status': status,
            'size': size
        }

    except:
        return None


def analyze_logs(log_file, threshold=10):
    ip_404_count = defaultdict(int)
    ip_total_count = defaultdict(int)

    total_lines = 0
    parsed_lines = 0
    error_lines = 0
    total_404 = 0

    try:
        with open(log_file, 'r', errors='ignore') as f:
            for line in f:
                total_lines += 1

                entry = parse_log_entry(line)

                if entry is None:
                    error_lines += 1
                    continue

                parsed_lines += 1

                ip = entry['ip']
                status = entry['status']

                ip_total_count[ip] += 1

                if status == 404:
                    ip_404_count[ip] += 1
                    total_404 += 1

    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.END}")
        return None

    flagged = {}

    for ip, count in ip_404_count.items():
        if count >= threshold:
            total = ip_total_count[ip]
            percent = (count / total) * 100

            flagged[ip] = {
                '404': count,
                'total': total,
                'percent': percent
            }

    return {
        'total_lines': total_lines,
        'parsed_lines': parsed_lines,
        'error_lines': error_lines,
        'total_404': total_404,
        'unique_ips': len(ip_total_count),
        'flagged': flagged
    }


def generate_report(data, threshold, file):
    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.CYAN}404 ERROR DETECTION REPORT{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}\n")

    print(f"{Colors.BLUE}[*] File: {file}{Colors.END}")
    print(f"{Colors.BLUE}[*] Threshold: {threshold}{Colors.END}")
    print(f"{Colors.BLUE}[*] Time: {datetime.now()}{Colors.END}\n")

    print("Total lines:", data['total_lines'])
    print("Parsed lines:", data['parsed_lines'])
    print("Errors:", data['error_lines'])
    print("Unique IPs:", data['unique_ips'])
    print("Total 404:", data['total_404'], "\n")

    if not data['flagged']:
        print(f"{Colors.GREEN}[✓] No suspicious IPs detected{Colors.END}")
        return

    print(f"{Colors.RED}[!] Suspicious IPs:{Colors.END}\n")

    for ip, d in data['flagged'].items():
        print(f"{Colors.YELLOW}IP: {ip}{Colors.END}")
        print(f"404 Count: {d['404']}")
        print(f"Total Requests: {d['total']}")
        print(f"Error %: {d['percent']:.2f}%\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile")
    parser.add_argument("--threshold", type=int, default=10)

    args = parser.parse_args()

    print(f"{Colors.CYAN}[*] Starting Analysis...{Colors.END}")

    result = analyze_logs(args.logfile, args.threshold)

    if result:
        generate_report(result, args.threshold, args.logfile)