# ===========================================
# Network Log Analyzer
# A beginner cybersecurity project
# Detects brute force attacks, port scans,
# and suspicious after-hours activity
# by Freddys
# ===========================================

import pandas as pd
import matplotlib.pyplot as plt

# --------------------------------------------------
# FUNCTION: load_data
# Reads the network log CSV file and returns
# it as a pandas DataFrame
# --------------------------------------------------
def load_data():
    df = pd.read_csv('network_logs.csv')
    print(df)
    return df

# --------------------------------------------------
# FUNCTION: detect_threats
# Analyzes the log data to find:
#   - IPs with too many failed logins
#   - Activity outside business hours
# Exports a threat report to threat_report.csv
# --------------------------------------------------
def detect_threats(df):
    # Filter for failed login events only
    failed = df[df['event_type'] == 'failed_login']

    # Count failed logins per IP address
    failed_counts = failed.groupby('ip_address').size()
    print("\nFailed logins per IP address:")
    print(failed_counts)

    # Flag IPs that exceed the suspicious threshold (3+)
    suspicious = failed_counts[failed_counts >= 3]
    print("\nSuspicious IPs (3 or more failed logins):")
    print(suspicious)

    # Print a human-readable alert for each suspicious IP
    for ip in suspicious.index:
        count = suspicious[ip]
        print(f"\n⚠️  ALERT: {ip} has {count} failed logins — possible brute force attack!")

    # Build a threat report with severity levels
    # HIGH = 10 or more failed logins, MEDIUM = under 10
    report = pd.DataFrame({
        'ip_address': suspicious.index,
        'failed_logins': suspicious.values,
        'threat_level': ['HIGH' if x >= 10 else 'MEDIUM' for x in suspicious.values]
    })
    report.to_csv('threat_report.csv', index=False)
    print("\n📝 Threat report saved as threat_report.csv")

    # Detect events outside business hours (before 8am or after 6pm)
    df['hour'] = df['timestamp'].str.split(':').str[0].astype(int)
    unusual = df[(df['hour'] < 8) | (df['hour'] >= 18)]
    if len(unusual) > 0:
        print(f"\n🌙 ALERT: {len(unusual)} events detected outside business hours!")
        print(unusual[['timestamp', 'ip_address', 'event_type']])

    return failed_counts

# --------------------------------------------------
# FUNCTION: show_charts
# Generates a three panel dashboard showing:
#   - Failed logins per IP
#   - Attack timeline
#   - Port activity breakdown
# Saves the dashboard as network_analysis.png
# --------------------------------------------------
def show_charts(failed_counts, df):
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(20, 5))

    # Chart 1: Bar chart of failed logins per IP address
    failed_counts.plot(kind='bar', color='red', ax=ax1)
    ax1.set_title('Failed Logins per IP Address')
    ax1.set_xlabel('IP Address')
    ax1.set_ylabel('Number of Failed Logins')

    # Chart 2: Line chart showing attack frequency over time
    timeline = df[df['event_type'] != 'success'].groupby('timestamp').size()
    timeline.plot(kind='line', color='orange', marker='o', ax=ax2)
    ax2.set_title('Attack Timeline')
    ax2.set_xlabel('Time')
    ax2.set_ylabel('Number of Attacks')
    plt.xticks(rotation=45)

    # Chart 3: Bar chart of which ports were targeted most
    port_counts = df.groupby('port').size()
    port_counts.plot(kind='bar', color='purple', ax=ax3)
    ax3.set_title('Attacks by Port Number')
    ax3.set_xlabel('Port')
    ax3.set_ylabel('Number of Events')

    # Save and display the dashboard
    plt.tight_layout()
    plt.savefig('network_analysis.png', dpi=150, bbox_inches='tight')
    print("\n📊 Chart saved as network_analysis.png")
    plt.show()

# --------------------------------------------------
# MAIN: Run the analyzer
# --------------------------------------------------
df = load_data()
failed_counts = detect_threats(df)
show_charts(failed_counts, df)