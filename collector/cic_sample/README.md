# CSE-CIC-IDS2018 sample

`sample_flows.csv` is a small excerpt in the exact column format of the
CSE-CIC-IDS2018 "Processed Traffic Data for ML Algorithms" files, used by
`tests/test_cic_flows.py`. Only the columns the reader uses carry real values.

The full dataset is not committed (each day's CSV is 100 MB–4 GB). To use it:

```bash
mkdir -p ~/cic-ids2018 && cd ~/cic-ids2018
curl -o 2018-02-14.csv "https://cse-cic-ids2018.s3.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"
cd ~/CSCE4907/Capstone
python3 collector/cic_flows.py ~/cic-ids2018/2018-02-14.csv --summary-only
python3 collector/cic_flows.py ~/cic-ids2018/2018-02-14.csv --labels SSH-Bruteforce,FTP-BruteForce,Benign --every 100 -o cic_events.json
```

## What we found in the dataset

- The raw "Network Traffic and Log data" includes syslog files from the
  Ubuntu servers (`logs/U172.31.69.*`), in the same format our collector reads.
  On the SSH/FTP brute-force day (Feb 14) and the web-attack day (Feb 22) they
  contain no sshd, FTP or web-request lines: authentication and web access logs
  were not captured. The collector read all 1,413 Feb 14 lines and correctly
  produced no security events.
- The attacks are therefore only visible in the labeled flow CSVs, which have
  destination port, protocol, timestamp and label but no IP addresses.

## Citation

Iman Sharafaldin, Arash Habibi Lashkari and Ali A. Ghorbani, "Toward Generating
a New Intrusion Detection Dataset and Intrusion Traffic Characterization",
ICISSP 2018. Dataset: CSE-CIC-IDS2018, Communications Security Establishment and
Canadian Institute for Cybersecurity, https://www.unb.ca/cic/datasets/ids-2018.html
