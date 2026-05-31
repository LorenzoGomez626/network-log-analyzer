# 🔐 Network Log Analyzer

A Python-based cybersecurity tool that analyzes network logs to detect suspicious activity, brute force attacks, and unusual access patterns.

Built as a beginner cybersecurity project to demonstrate real-world log analysis techniques using Python, pandas, and matplotlib.

---

## 📋 What It Does

- Loads network log data from a CSV file
- Detects IPs with too many failed login attempts (brute force detection)
- Scores each threat automatically as HIGH or MEDIUM severity
- Flags any activity that happens outside business hours (before 8am or after 6pm)
- Generates a three panel visual dashboard of attack patterns
- Exports a threat report to a CSV file automatically

---

## 📊 Output

The program generates three files automatically:

| File | Description |
|------|-------------|
| `network_analysis.png` | Three panel chart dashboard showing attack patterns |
| `threat_report.csv` | Severity scored report of all suspicious IPs |
| `network_logs.csv` | The full network log dataset |

---

## 🚨 Attack Types Detected

| Attack Type | Description |
|-------------|-------------|
| Brute Force | IP addresses with 3 or more failed login attempts |
| Port Scan | Attempts to probe multiple ports looking for vulnerabilities |
| After Hours Activity | Any network events outside of normal business hours |

---

## 🛠️ How To Run It

Make sure you have Python installed along with the required libraries:

```bash
pip install pandas matplotlib
```

Then run the analyzer:

```bash
python security_analysis.py
```

---

## 📁 Project Files

network-log-analyzer/
│
├── security_analysis.py   # Main analyzer script
├── network_logs.csv       # Network log dataset
├── threat_report.csv      # Generated threat report
├── network_analysis.png   # Generated chart dashboard
└── README.md              # Project documentation

---

## 🧠 Concepts Demonstrated

- Data loading and analysis with **pandas**
- Data visualization with **matplotlib**
- Cybersecurity concepts: brute force detection, port scanning, threat scoring
- Clean code organization using **functions**
- Exporting reports to **CSV**

---

## 👤 Author

Built by Freddys