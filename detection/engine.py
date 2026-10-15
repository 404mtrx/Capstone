from rules import detect_failed_login


def analyze_event(event):
    alert = detect_failed_login(event)

    if alert:
        return alert

    return None


if __name__ == "__main__":

   test_event = {
       "timestamp": "2026-10-08T01:30:00Z",
       "source": "linux_auth",
       "event_type": "failed_login",
       "username": "admin",
       "source_ip": "192.168.1.25",
       "destination_ip": "192.168.1.10",
       "destination_port": 22,
       "hostname": "server1",
       "protocol": "SSH",
       "event_id": None,
       "process_name": "sshd",
       "action": "failure",
       "severity": "medium",
       "message": "Failed password for admin from 192.168.1.25"
   }

   result = analyze_event(test_event)
   print(result)
