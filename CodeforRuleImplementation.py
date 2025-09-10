import pandas as pd
import numpy as np
import random
import datetime
import matplotlib.pyplot as plt

# -------------------------------
# 1. Synthetic Dataset Generation
# -------------------------------
np.random.seed(42)

users = ["alice", "bob", "charlie", "dave", "eve"]
roles = ["user", "analyst", "admin"]
ips = [f"192.168.1.{i}" for i in range(1, 50)]
locations = ["Germany", "USA", "India", "UK"]
commands = ["ls", "cat", "netstat", "whoami"]  # Removed suspicious commands from general set for more normal logs
resources = ["public_data", "internal_docs", "confidential_data", "prod_server"]

logs = []
start_time = datetime.datetime(2025, 1, 1, 8, 0, 0)

# Increased dataset size and skewed toward normal behavior for more non-alert logs
for i in range(3000):
    user = random.choice(users)
    role = random.choice(roles)
    ip = random.choice(ips)
    location = random.choice(locations)
    # More safe commands to increase non-alert logs
    if random.random() < 0.7:
        command = random.choice(["ls", "cat", "netstat", "whoami"])
    else:
        command = random.choice(["rm -rf", "sudo su", "scp", "reboot"])
    email_attachments = random.randint(0, 50 if random.random() < 0.3 else 15)
    privileged_action = random.choice([True, False]) if random.random() < 0.2 else False
    role_change = random.choice([True, False]) if random.random() < 0.2 else False
    change_request = random.choice(["CR123", "CR456", None])
    resource = random.choice(resources)
    access_type = random.choice(["success", "fail"])
    timestamp = start_time + datetime.timedelta(minutes=random.randint(0, 10000))

    logs.append({
        "timestamp": timestamp,
        "user": user,
        "role": role,
        "ip": ip,
        "location": location,
        "command": command,
        "email_attachments": email_attachments,
        "privileged_action": privileged_action,
        "role_change": role_change,
        "change_request": change_request,
        "resource": resource,
        "access_type": access_type
    })

logs_df = pd.DataFrame(logs)

# -------------------------------
# 2. Rule Engine Implementation (1 alert per row)
# -------------------------------
def detect_alerts_one_per_row(df):
    alert_rows = []

    for idx, row in df.iterrows():
        user_logs = df[(df['user'] == row['user']) & (df['timestamp'] < row['timestamp'])]
        recent_logs = user_logs[user_logs['timestamp'] > row['timestamp'] - pd.Timedelta(minutes=30)]
        rare_commands = ["rm -rf", "sudo su", "reboot"]

        # R1: Lateral Movement
        if len(user_logs['ip'].unique()) > 3:
            alert_rows.append({**row.to_dict(), "alert": "R1: Lateral Movement"})

        # R2: Rapid Multi-System Access
        if len(recent_logs['ip'].unique()) > 2:
            alert_rows.append({**row.to_dict(), "alert": "R2: Rapid Multi-System Access"})

        # R3: Location/IP Anomaly
        if len(user_logs['location'].unique()) > 1:
            alert_rows.append({**row.to_dict(), "alert": "R3: Location/IP Anomaly"})

        # R4: Role Change + Privileged Activity
        if row['role_change'] and row['privileged_action']:
            alert_rows.append({**row.to_dict(), "alert": "R4: Role Change + Privileged Activity"})

        # R5: Mass email attachment
        if row['email_attachments'] > 20:
            alert_rows.append({**row.to_dict(), "alert": "R5: Mass Email Attachment"})

        # R6: Rare Command Usage by Non-Privileged Users
        if row['command'] in rare_commands and row['role'] != "admin":
            alert_rows.append({**row.to_dict(), "alert": "R6: Rare Command by Non-Privileged User"})

        # R7: Repeated Failed Access Attempts to confidential data
        if row['resource'] == "confidential_data" and row['access_type'] == "fail" and row['role'] != "admin":
            recent_fails = recent_logs[(recent_logs['resource'] == "confidential_data") & (recent_logs['access_type'] == "fail")]
            if len(recent_fails) > 5:
                alert_rows.append({**row.to_dict(), "alert": "R7: Repeated Failed Access Attempts"})

        # R8: Restricted Access to Production Server at odd hours (00:00-05:00)
        if row['resource'] == "prod_server" and row['timestamp'].hour < 5:
            if not (row['role'] == "admin" and row['change_request'] is not None):
                alert_rows.append({**row.to_dict(), "alert": "R8: Restricted Prod Access at Odd Hours"})

        # Include normal log with empty alert
        if not any([
            len(user_logs['ip'].unique()) > 3,
            len(recent_logs['ip'].unique()) > 2,
            len(user_logs['location'].unique()) > 1,
            (row['role_change'] and row['privileged_action']),
            row['email_attachments'] > 20,
            (row['command'] in rare_commands and row['role'] != "admin"),
            (row['resource'] == "confidential_data" and row['access_type'] == "fail" and row['role'] != "admin" and len(recent_logs[(recent_logs['resource'] == "confidential_data") & (recent_logs['access_type'] == "fail")]) > 5),
            (row['resource'] == "prod_server" and row['timestamp'].hour < 5 and not (row['role'] == "admin" and row['change_request'] is not None))
        ]):
            alert_rows.append({**row.to_dict(), "alert": ""})

    return pd.DataFrame(alert_rows)

merged_df = detect_alerts_one_per_row(logs_df)
merged_df.to_csv("Insider_threats_alerts.csv", index=False)

print("Merged dataset with one alert per row saved as Insider_threats_alerts.csv")

# -------------------------------
# 3. Visual Dashboards
# -------------------------------
alerts_only = merged_df[merged_df['alert'] != ""]

# Alerts over time
alerts_per_day = alerts_only.groupby(alerts_only['timestamp'].dt.date).size()
plt.figure(figsize=(8, 4))
alerts_per_day.plot(kind='line', marker='o')
plt.title("Alerts Over Time")
plt.xlabel("Date")
plt.ylabel("Number of Alerts")
plt.grid(True)
plt.tight_layout()
plt.savefig("alerts_over_time.png")

# Rule frequency
rule_counts = alerts_only['alert'].value_counts()
plt.figure(figsize=(8, 4))
rule_counts.plot(kind='bar')
plt.title("Rule Frequency")
plt.xlabel("Rule")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig("rule_frequency.png")

# Pie chart of roles involved in alerts
role_counts = alerts_only['role'].value_counts()
plt.figure(figsize=(5, 5))
role_counts.plot(kind='pie', autopct='%1.1f%%')
plt.title("Roles in Alerts")
plt.ylabel("")
plt.tight_layout()
plt.savefig("roles_in_alerts.png")




