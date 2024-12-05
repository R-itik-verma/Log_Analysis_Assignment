import re
import pandas as pd
import csv

LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 2

def parse_log_file(log_file):
    log_data = []
    pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+).+?"(?P<method>\w+) (?P<endpoint>/\S+).*?" (?P<status>\d+)'
    
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(pattern, line)
            if match:
                log_data.append({
                    'ip': match.group('ip'),
                    'endpoint': match.group('endpoint'),
                    'status': int(match.group('status'))
                })
    return log_data

def analyze_data(log_data):
    ip_counts = {}
    endpoint_counts = {}
    failed_login_attempts = {}

    for entry in log_data:
        ip = entry['ip']
        endpoint = entry['endpoint']
        status = entry['status']

        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1

        if status == 401:
            failed_login_attempts[ip] = failed_login_attempts.get(ip, 0) + 1

    most_accessed_endpoint = max(endpoint_counts, key=endpoint_counts.get)
    suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD}

    return ip_counts, endpoint_counts, most_accessed_endpoint, suspicious_ips


def save_to_csv(ip_counts, endpoint_counts, most_accessed_endpoint, suspicious_ips, output_csv):
    with open(output_csv, 'w') as file:
        file.write("Requests per IP\n")
        file.write(f"{'IP Address':<20}{'Request Count':<15}\n")  
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
            file.write(f"{ip:<20}{count:<15}\n")  

        file.write("\n") 

        
        file.write("Most Accessed Endpoint\n")
        file.write(f"{'Endpoint':<20}{'Access Count':<15}\n")
        file.write(f"{most_accessed_endpoint:<20}{endpoint_counts[most_accessed_endpoint]:<15}\n")

        file.write("\n")  

        
        file.write("Suspicious Activity\n")
        file.write(f"{'IP Address':<20}{'Failed Login Count':<15}\n")
        for ip, count in suspicious_ips.items():
            file.write(f"{ip:<20}{count:<15}\n")  

    print(f"Results saved to {output_csv}")

def main():
    log_data = parse_log_file(LOG_FILE)
    ip_counts, endpoint_counts, most_accessed_endpoint, suspicious_ips = analyze_data(log_data)
    print("IP Request Counts:", ip_counts)
    print("Most Accessed Endpoint:", most_accessed_endpoint)
    print("Suspicious IPs:", suspicious_ips)
    save_to_csv(ip_counts, endpoint_counts, most_accessed_endpoint, suspicious_ips, OUTPUT_CSV)

if __name__ == "__main__":
    main()
