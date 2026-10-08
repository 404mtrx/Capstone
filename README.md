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


## Sensitive Data

SentinelWatch may process and store sensitive security information, including:

(1). Usernames and account information
(2). Source and destination IP addresses
(3). Authentication events
(4). Security logs and normalized event data
(5). Alert details
(6). Case and investigation notes
(7). User roles and access permissions

## Logging Requirements
(1). Support 2–3 initial log sources
(2). Collect authentication and security-related events
(3). Preserve the original message
(4). Extract important fields such as timestamp, username, source IP, destination IP, and event type
(5). Normalize logs into the common event schema
(6). Store normalized events in OpenSearch
(7). Make events searchable and available to the detection engine
(8). Handle missing optional fields using null
