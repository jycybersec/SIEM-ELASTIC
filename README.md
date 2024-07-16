# ELK (Elasticsearch, Logstash, and Kibana) SIEM Implementation

## Agent Deployment 
- #1 Kali Purple "purplesec"
  ![image](https://github.com/user-attachments/assets/6d691106-619d-4a1d-8a8e-0d2ff4d49c5e)
- #2 Kali OffSec "jycybersec"
  ![image](https://github.com/user-attachments/assets/107a6332-a6a2-4735-985a-34f005240e95)
- #3 Windows 10 "windows10"
  ![image](https://github.com/user-attachments/assets/cf7d853c-df92-428d-9641-345a91803f52)
- #4 Windows 11 x64 "windows11"
  ![image](https://github.com/user-attachments/assets/0996a2c8-0698-4f00-8735-3a2fe3cd525e)
- Agent Fleet
  ![image](https://github.com/user-attachments/assets/00c6ce90-e0e0-491b-bf13-4e92e77c113e)

## Define Rule Details

For each rule, we will:

  - Define the **index patterns** to search:
    - We'll use index patterns such as `logs-*`, `filebeat-*`, and `packetbeat-*` to ensure comprehensive coverage of relevant logs and data sources.

  - Specify the **query** to match the suspicious activity:
    - For **Excessive Login Failures**, the query is `event.type:authentication_failure` to detect failed login attempts.
    - For **Unusual Network Traffic**, the query is `network.direction:outbound and not network.ip:internal` to identify outbound traffic to external IPs.
    - For **Suspicious File Execution**, the query is `event.action:process_start and file.path:(/tmp/* or /dev/shm/*)` to detect process starts from uncommon directories.

  - Apply any **additional filters** or **machine learning jobs** to refine the detection:
    - For **Excessive Login Failures**, we set a threshold of more than 5 failed login attempts from the same IP within 10 minutes.
    - For **Unusual Network Traffic**, we set a threshold to detect a 50% increase in outbound traffic to rare external IPs not seen in the last 30 days.
    - For **Suspicious File Execution**, we monitor for process starts from specific uncommon directories like `/tmp` and `/dev/shm`.
      
  - Define actions to take when the rule is triggered:
    - For each rule, we send an email notification to `jycybersec@gmail.com` to alert of possible malicous activity.

## Detection Rules Setup

### 1. Excessive Login Failures
- **Rule**: Detect multiple failed login attempts within a short time frame.
- **Condition**: More than 5 failed login attempts from the same IP within 10 minutes.
- **Trigger**: Monitor authentication logs for `event.type:authentication_failure`.
- **Detection Rule**: 
```JSON
{"rule_id":"excessive_login_failures",
"name":"Excessive Login Failures",
"description":"Detects multiple failed login attempts from the same IP within 10 minutes.",
"risk_score":21,
"severity":"medium",
"type":"threshold",
"index":["logs-*","filebeat-*","packetbeat-*"],
"language":"kuery",
"query":"event.type:authentication_failure",
"threshold":{"field":["source.ip"],"value":5,
"interval":"10m",
"from":"now-10m",
"actions":[{"group":"default",
"id":"elastic-cloud-email",
"action_type_id":".email",
"params":{"to":["jycybersec@gmail.com"],
"subject":"Multiple failed login attempts detected",
"message":"More than 5 failed login attempts from the same IP within 10 minutes."}}]}
```
### Manual Setup
![image](https://github.com/user-attachments/assets/31a7bd23-1b94-4614-8ce3-2bcd2d583e32)

![image](https://github.com/user-attachments/assets/572976b4-5e63-42ab-aa5f-87c011c32f4f)

![image](https://github.com/user-attachments/assets/ae1d4b0f-e750-4386-b124-f9ba95186d41)


### 2. Unusual Network Traffic
- **Rule**: Identify sudden spikes in network traffic to unusual destinations.
- **Condition**: An increase of 50% in outbound traffic to a rare external IP address not seen in the last 30 days.
- **Trigger**: Use network flow data and analyze against historical baselines with `network.direction:outbound`.
- **Detection Rule**:
```JSON
{"rule_id":"unusual_network_traffic",
"name":"Unusual Network Traffic",
"description":"Detects unusual outbound network traffic with a significant increase.",
"type":"query",
"index":["logs-*","filebeat-*","packetbeat-*"],
"language":"kuery",
"query":"network.direction:outbound and not network.ip:internal",
"threshold.field":"destination.ip",
"threshold.value":1,
"threshold.cardinality":[{"field":"source.ip","value":"50%"}],
"timeframe":"last 30d",
"risk_score":70,
"severity":"high",
"actions":[{"group":"default",
"id":"elastic-cloud-email",
"action_type_id":".email",
"params":{"to":["jycybersec@gmail.com"],
"subject":"Unusual outbound network traffic detected",
"message":"Increase of 50% or more in outbound traffic to a rare external IP not seen in the last 30 days."}}]}
```
![image](https://github.com/user-attachments/assets/09ed91ba-5447-441d-a235-35ad1bad59da)

![image](https://github.com/user-attachments/assets/d0993332-0aa1-45ee-8a20-71519753b6d4)

### 3. Suspicious File Execution
- **Rule**: Alert on execution of files from uncommon directories.
- **Condition**: Any `process.start` event where the file path is outside of standard directories.
- **Trigger**: Look for process execution logs with `event.action:process_start` and `file.path:/tmp/*`.
- **Detection Rule**:
```JSON
{"rule_id":"suspicious_file_execution",
"name":"Suspicious File Execution",
"description":"Detects process start events from suspicious file paths.",
"type":"query",
"index":["logs-*","filebeat-*","packetbeat-*"],
"language":"kuery",
"query":"event.action:process_start and file.path:(/tmp/* or /dev/shm/*)",
"risk_score":50,
"severity":"medium",
"actions":[{"group":"default","id":"elastic-cloud-email",
"action_type_id":".email",
"params":{"to":["jycybersec@gmail.com"],
"subject":"Suspicious file execution detected",
"message":"A process was started from /tmp or /dev/shm which is uncommon and could be suspicious."}}]}
```
![image](https://github.com/user-attachments/assets/84d68b5f-4aa3-4778-9116-6b06f5c676f9)

![image](https://github.com/user-attachments/assets/9f093b95-fdf7-42d2-b596-719e63b8ac54)

### 4. Data Exfiltration Attempts
- **Rule**: Detect large data transfers to external destinations.
- **Condition**: Any data transfer over 500 MB to an external domain not on the internal network.
- **Trigger**: Monitor data transfer logs for `event.type:data_transfer and destination.bytes > 500000000` and `destination.ip:192.168.0.0/16 or destination.ip:10.0.0.0/8`.
- **Detection Rule**:
```JSON
{"rule_id": "data_exfiltration_attempts",
"name": "Data Exfiltration Attempts",
"description": "Detects data transfer over 500MB to an external domain not on the internal network.",
"type": "query", 
"index": ["logs-*", "filebeat-*", "packetbeat-*"], 
"language": "kuery",
"query": "event.type:data_transfer and destination.bytes > 500000000 and not (destination.ip:192.168.0.0/16 or destination.ip:10.0.0.0/8)",
"risk_score": 80,
"severity":"high",
"actions": [{"action_type_id": ".email",
"group": "default",
"id": "elastic-cloud-email",
"params": {"to": ["jycybersec@gmail.com"],
"subject": "Potential data exfiltration attempt detected",
"message": "Data transfer over 500MB to an external domain not on the internal network."}}]}
```
![image](https://github.com/user-attachments/assets/0ba9765b-f037-4ff6-8b45-3a40a54a4322)

![image](https://github.com/user-attachments/assets/c3502b35-38e4-46f3-bf04-a59c6e639224)

## Attack Simulation

### 1. Excessive Login Failures
- **Technique**: Brute force attack with various username and password combinations.

### 2. Unusual Network Traffic
- **Technique**: Data exfiltration over a different protocol or port to avoid detection.

### 3. Suspicious File Execution
- **Technique**: Execution of malware payload from a temporary directory or user profile.

### . Data Exfiltration Attempts
- **Technique**: Compression and encryption of sensitive data before exfiltration.

## Mitigation Strategies

### 1. Excessive Login Failures
- **Mitigation**: Implement account lockout policies and monitor for repeated authentication failures.

### 2. Unusual Network Traffic
- **Mitigation**: Employ network segmentation and egress filtering, and monitor for unusual traffic patterns.

### 3. Suspicious File Execution
- **Mitigation**: Restrict execution from non-standard directories and monitor process creation events.

### 4. Data Exfiltration Attempts
- **Mitigation**: Monitor for large outbound transfers and any use of compression or encryption tools not typically used.
