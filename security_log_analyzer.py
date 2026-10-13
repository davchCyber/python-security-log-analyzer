import datetime

def read_logs(filename):
    logs = []
    with open(filename, 'r') as file:
        for line in file:
            
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 5:
                continue
            username = parts[2].replace('user=', '')
            ip = parts[3].replace('ip=', '')
            result = parts[4].replace('result=', '')
            timestamp = parts[0] + ' ' + parts[1]
            log_entry = {
                            'timestamp': timestamp,
                            'user': username,
                            'ip': ip,
                            'result': result
                        }
            logs.append(log_entry)
    return logs
        

def analyze_logs(logs):
    user_stats = {}

    for info in logs:
        if info['user'] not in user_stats:
            user_stats[info['user']] = {
                'failed': 0,
                'success': 0
            }

        if info['result'] == 'failed':
            user_stats[info['user']]['failed'] += 1
        else:
            user_stats[info['user']]['success'] += 1

    return user_stats

def most_failed_user(user_stats):
    max_failed = 0
    max_failed_user = ''

    for user, stats in user_stats.items():

        if stats['failed'] > max_failed:
            max_failed = stats['failed']
            max_failed_user = user

    return max_failed_user

def failure_rates(user_stats):
    rates = {}

    for user, stats in user_stats.items():

        total = stats['failed'] + stats['success']
        rate = stats['failed'] / total * 100

        rates[user] = round(rate, 1)

    return rates

threshold = 50
def detect_high_failure_rates(user_stats, threshold):
    suspicious_users = {}
    for user, stats in user_stats.items():
        total = stats['failed'] + stats['success']

        rate = stats['failed'] / total * 100

        if rate > threshold:
            suspicious_users[user] = round(rate, 1)

    return suspicious_users

def generate_alerts(suspicious_users):
    for user, rate in suspicious_users.items():
        print(f"ALERT: {user} has a {rate}% login failure rate.")

def analyze_ips(logs):
    ip_stats = {}

    for info in logs:
        if info['ip'] not in ip_stats:
            ip_stats[info['ip']] = {
                'failed': 0,
                'success': 0,
                'users': []
            }
        if info['user'] not in ip_stats[info['ip']]['users']:
            ip_stats[info['ip']]['users'].append(info['user'])
        if info['result'] == 'failed':
            ip_stats[info['ip']]['failed'] += 1
        else:
            ip_stats[info['ip']]['success'] += 1
    return ip_stats


time_window = 60
ip_failure_threshold = 3
def detect_brute_force(ip_stats, ip_failure_threshold):
    suspicious_ips = {}
    for ip, stats in ip_stats.items():
        if stats['failed'] > ip_failure_threshold:
            suspicious_ips[ip] = stats

    return suspicious_ips

def generate_ip_alerts(suspicious_ips):
    for ip, stats in suspicious_ips.items():
        print("BRUTE FORCE ALERT")
        print(f"IP: {ip}")
        print(f"Failed attempts: {stats['failed']}")
        print(f"Targeted Users: {', '.join(stats['users'])}")

def detect_brute_force_window(logs, ip_failure_threshold, time_window):
    failed_attempts = {}

    for info in logs:
        if info['result'] == 'failed':
            ip = info['ip']
            
            if ip not in failed_attempts:
                failed_attempts[ip] = []

            failed_attempts[ip].append(info['timestamp'])

    suspicious_ips = {}

    for ip, timestamps in failed_attempts.items():
        parsed_times = []

        for timestamp in timestamps:
            parsed_time = datetime.datetime.strptime(
                timestamp, '%Y-%m-%d %H:%M:%S'
            )
            parsed_times.append(parsed_time)
        parsed_times.sort()

        for i in range(len(parsed_times)):
            window_start = parsed_times[i]
            attempts = 0

            for timestamp in parsed_times[i:]:
                difference = timestamp - window_start

                if difference.total_seconds() <= time_window:
                    attempts += 1
                else:
                    break
            if attempts > ip_failure_threshold:
                window_end = parsed_times[i + attempts - 1]
                duration = (window_end - window_start).total_seconds()

                suspicious_ips[ip] = {
                    'failed': attempts,
                    'window_start': window_start.strftime('%Y-%m-%d %H:%M:%S'),
                    'window_end': window_end.strftime('%Y-%m-%d %H:%M:%S'),
                    'duration_seconds': duration
                }
                break

    return suspicious_ips

            

logs = read_logs(r'C:\Users\NYIsl\Desktop\School\Python\sample_auth.log')

user_stats = analyze_logs(logs)
suspicious = detect_high_failure_rates(user_stats, threshold)

generate_alerts(suspicious)
print("Suspicious:",suspicious)
print("User Failure Rates:",failure_rates(user_stats))
print("Most Failed User:",most_failed_user(user_stats))
ip_stats = analyze_ips(logs)
print("IP Statistics:",ip_stats)
suspicious_ips = detect_brute_force(ip_stats, ip_failure_threshold)
print("Suspicious IPs:", suspicious_ips)
generate_ip_alerts(suspicious_ips)

window_alerts = detect_brute_force_window(
    logs, ip_failure_threshold, time_window
)
print("Time-window alerts:", window_alerts)
