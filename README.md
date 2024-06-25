# Elastic SIEM Implementation

## Agent Deployment 
An agent will be deployed on each intended machine.
- #1 Kali Purple
- #2 Kali OffSec
- #3 Metasploitable Linux
- #4 Metasploitable Windows 2008
- #5 Windows XP

## Manage Detection Rules
- Open the Elastic SIEM app.
- Click on the **Detections** tab.
- Select **Manage detection rules**.
- Choose to **create new rules** or **import** them if you have the JSON rule definitions.

## Define Rule Details
For each rule, we will:
- Define the **index patterns** to search.
- Specify the **query** to match the suspicious activity.
- Apply any **additional filters** or **machine learning jobs** to refine the detection.

## Detection Rules Setup

### 1. Excessive Login Failures
- **Rule**: Detect multiple failed login attempts within a short time frame.
- **Condition**: More than 5 failed login attempts from the same IP within 10 minutes.
- **Trigger**: Monitor authentication logs for `event.type:authentication_failure`.
- **Detection**: 
```yaml
- id: excessive_login_failures
  name: Excessive Login Failures
  type: threshold
  index: ["logs-*", "filebeat-*", "packetbeat-*"]
  language: kuery
  query: "event.type:authentication_failure"
  threshold:
    field: "source.ip"
    value: 5
  timeframe: "last 10m"
  risk_score: 21
  severity: medium
  actions:
    - alert:
        summary: "Multiple failed login attempts detected"
        description: "More than 5 failed login attempts from the same IP within 10 minutes."

```

### 2. Unusual Network Traffic
- **Rule**: Identify sudden spikes in network traffic to unusual destinations.
- **Condition**: An increase of 50% in outbound traffic to a rare external IP address not seen in the last 30 days.
- **Trigger**: Use network flow data and analyze against historical baselines with `network.direction:outbound`.
- **Detection**:
```yaml
- rule_id: unusual_network_traffic
  name: Unusual Network Traffic
  type: query
  index: ["logs-*", "filebeat-*", "packetbeat-*"]
  language: kuery
  query: "network.direction:outbound and not network.ip:internal"
  threshold:
    field: "destination.ip"
    value: 1
    cardinality:
      - field: "source.ip"
        value: "50%"
  timeframe: "last 30d"
  risk_score: 70
  severity: high
  actions:
    - alert:
        summary: "Unusual outbound network traffic detected"
        description: "Increase of 50% or more in outbound traffic to a rare external IP not seen in the last 30 days."
```

### 3. Suspicious File Execution
- **Rule**: Alert on execution of files from uncommon directories.
- **Condition**: Any `process.start` event where the file path is outside of standard directories.
- **Trigger**: Look for process execution logs with `event.action:process_start` and `file.path:/tmp/*`.
- **Detection**:
```yaml
- rule_id: suspicious_file_execution
  name: Suspicious File Execution
  type: query
  index: ["logs-*", "filebeat-*", "packetbeat-*"]
  language: kuery
  query: "event.action:process_start and file.path:(/tmp/* or /dev/shm/*)"
  risk_score: 50
  severity: medium
  actions:
    - alert:
        summary: "Suspicious file execution detected"
        description: "Process started from /tmp or other uncommon directories."
```


### 4. Anomalous User Behavior
- **Rule**: Detect when a user accesses resources atypical to their normal behavior.
- **Condition**: User account accessing more than 3 servers or databases not accessed in the last 60 days.
- **Trigger**: Correlate user access logs with `event.category:user_access` and behavioral analytics.
- **Detection**:
```yaml
- rule_id: anomalous_user_behavior
  name: Anomalous User Behavior
  type: query
  index: ["logs-*", "filebeat-*", "packetbeat-*"]
  language: kuery
  query: "event.category:user_access and not user.account.name:known_good"
  risk_score: 60
  severity: medium
  actions:
    - alert:
        summary: "Anomalous user behavior detected"
        description: "User account accessed more than 3 servers or databases not accessed in the last 60 days."
```


### 5. Data Exfiltration Attempts
- **Rule**: Spot large data transfers to external destinations.
- **Condition**: Any data transfer over 500 MB to an external domain not on the corporate whitelist.
- **Trigger**: Monitor data transfer logs for `event.type:data_transfer` and `destination.domain:!*company_whitelist*`.
- **Detection**:
```yaml
- rule_id: data_exfiltration_attempts
  name: Data Exfiltration Attempts
  type: query
  index: ["logs-*", "filebeat-*", "packetbeat-*"]
  language: kuery
  query: "event.type:data_transfer and destination.bytes > 500000000 and not destination.ip:internal"
  risk_score: 80
  severity: high
  actions:
    - alert:
        summary: "Potential data exfiltration attempt detected"
        description: "Data transfer over 500MB to an external domain not on the corporate whitelist."
```


## Attack Simulation

### 1. Excessive Login Failures
- **Technique**: Brute force attack with various username and password combinations.

### 2. Unusual Network Traffic
- **Technique**: Data exfiltration over a different protocol or port to avoid detection.

### 3. Suspicious File Execution
- **Technique**: Execution of malware payload from a temporary directory or user profile.

### 4. Anomalous User Behavior
- **Technique**: Use of stolen credentials to access systems and data outside of normal behavior patterns.

### 5. Data Exfiltration Attempts
- **Technique**: Compression and encryption of sensitive data before exfiltration.

## Mitigation Strategies

### 1. Excessive Login Failures
- **Mitigation**: Implement account lockout policies and monitor for repeated authentication failures.

### 2. Unusual Network Traffic
- **Mitigation**: Employ network segmentation and egress filtering, and monitor for unusual traffic patterns.

### 3. Suspicious File Execution
- **Mitigation**: Restrict execution from non-standard directories and monitor process creation events.

### 4. Anomalous User Behavior
- **Mitigation**: Implement least privilege access controls and user behavior analytics.

### 5. Data Exfiltration Attempts
- **Mitigation**: Monitor for large outbound transfers and any use of compression or encryption tools not typically used.
