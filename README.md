# CSCE 4907 Cybersecurity Capstone
# Team - Netrunners


## Team member

               1.Satya Pun Magar
               2.Kritika Thapa Magar
               3.Matrika Timilsaina
               4.Aayan Nisar Zafar

## Description
SentinelWatch is a lightweight, self-hosted security platform that combines three core blue-team capabilities into one product:

(1) Collects and normalizes security logs from common sources into a consistent format for centralized storage and analysis.

(2) Applies rule-based detection and correlation to security events to identify suspicious activity and generate alerts.

(3) Presents security activity and alerts through a centralized SOC Dashboard that allows analysts to monitor events, review alerts, and perform basic case investigation.


## SentinelWatch Common Security Event Schema
We will use one flat common normalized event schema across the project. Different log sources will be converted into this same structure.
{
  "timestamp": "...",
  "source": "...",
  "event_type": "...",
  "username": "...",
  "source_ip": "...",
  "destination_ip": "...",
  "action": "...",
  "severity": "...",
  "message": "..."
}

These are the initial 9 core fields. If a future log source or detection rule needs additional information, we can extend the same schema with optional fields:
destination_port,
hostname,
protocol,
event_id,
process_name


## Planned Detection Rules

SentinelWatch will include approximately 10–15 rule-based detections, including:

(1). Multiple Failed Logins
(2). Successful Login After Multiple Failures
(3). Password Spraying
(4). Port Scan
(5). Repeated Blocked Connections
(6). High-Severity Event
(7). Account Lockout
(8). Privilege Change
(9). Suspicious Remote Login
(10). Repeated Access to Sensitive Ports
(11). Suspicious Activity From Same Source IP
(12). Repeated Authentication Across Hosts
