import re
from collections import defaultdict
import csv

# Configuration
LOG_FILE = "sample.log"
CSV_OUTPUT = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """Parses the log file and extracts relevant data."""
    logs = []
    with open(file_path, 'r') as file:
        for line in file:
            match = re.match(
                r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*\] "(?P<method>\w+) (?P<endpoint>\S+) HTTP/\d+\.\d+" (?P<status>\d+) (?P<size>\d+)',
                line
            )
            if match:
                logs.append(match.groupdict())
    return logs

def count_requests_per_ip(logs):
    """Counts the number of requests per IP address."""
    ip_counts = defaultdict(int)
    for log in logs:
        ip_counts[log['ip']] += 1
    return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

def most_frequently_accessed_endpoint(logs):
    """Finds the most frequently accessed endpoint."""
    endpoint_counts = defaultdict(int)
    for log in logs:
        endpoint_counts[log['endpoint']] += 1
    most_accessed = max(endpoint_counts.items(), key=lambda x: x[1])
    return most_accessed

def detect_suspicious_activity(logs, threshold):
    """Detects suspicious activity based on failed login attempts."""
    failed_attempts = defaultdict(int)
    for log in logs:
        if log['status'] == '401':  # Assuming 401 indicates failed login
            failed_attempts[log['ip']] += 1
    return {ip: count for ip, count in failed_attempts.items() if count > threshold}

def save_to_csv(requests, endpoint, suspicious, file_path):
    """Saves the analysis results to a CSV file."""
    with open(file_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        
        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(requests)
        writer.writerow([])  # Blank row
        
        # Write Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([endpoint[0], endpoint[1]])
        writer.writerow([])  # Blank row
        
        # Write Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious.items():
            writer.writerow([ip, count])

def main():
    logs = parse_log_file(LOG_FILE)
    
    # Count requests per IP
    requests = count_requests_per_ip(logs)
    print("IP Address           Request Count")
    for ip, count in requests:
        print(f"{ip:20} {count}")
    
    # Most frequently accessed endpoint
    endpoint = most_frequently_accessed_endpoint(logs)
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{endpoint[0]} (Accessed {endpoint[1]} times)")
    
    # Suspicious activity
    suspicious = detect_suspicious_activity(logs, FAILED_LOGIN_THRESHOLD)
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious.items():
        print(f"{ip:20} {count}")
    
    # Save results to CSV
    save_to_csv(requests, endpoint, suspicious, CSV_OUTPUT)
    print(f"\nResults saved to {CSV_OUTPUT}")

if __name__ == "__main__":
    main()
