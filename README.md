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
- Integrations
  ![image](https://github.com/user-attachments/assets/559e55d2-41a3-4e27-847c-25abb064b2df)


## Define Rule Details

For each rule, we will:

  - Define the **index patterns** to search:
    - We’ll use index patterns such as apm-*-transaction*, auditbeat-*, endgame-*, filebeat-*, logs-*, packetbeat-*, traces-apm*, winlogbeat-*, and -*elastic-cloud-logs-* to ensure comprehensive coverage of relevant logs and data sources.

  - Specify the **query** to match the suspicious activity:
    - For **Brute Force Attempt**, the query uses `event.code : "4625"` to detect failed login attempts.
    - For **Malicious Process Execution**, the query uses `process.args and process.command_line.text` to identify malicious process executions and specific commands.
    - For **Suspicious File Execution**, the query uses `event.action:process_start and file.path:(/tmp/* or /dev/shm/*)` to detect process starts from uncommon directories.
    - For **Data Exfiltration Attempts**, the query uses `event.type:data_transfer and destination.bytes > 500000000 and not (destination.ip:192.168.0.0/16 or destination.ip:10.0.0.0/8) ` to detect large data transfers to external destinations.

  - Apply any **additional filters** or **machine learning jobs** to refine the detection:
    - For *Brute Force Attempt**, we set a threshold of 5 failed login attempts.
    - For **Malicious Process Execution**, We monitor for process logs with specific malicious arguments.
    - For **Uncommon Directory File Execution**, we monitor for process starts from specific uncommon directories like `/tmp` and `/dev/shm`.
    - For **Data Exfiltration Attempts**, We set a threshold to detect any data transfer over 500 MB to an external domain not on the internal network.

## Detection Rules Setup

### 1. Brute Force Attempt
- **Rule**: Detect multiple failed login attempts within a short time frame.
- **Condition**: More than 5 failed login attempts from the same IP within 10 minutes.
- **Trigger**: Monitor authentication logs for `event.code : "4625"` (Login Failures).
- **Detection Rule**: 
```JSON
{"rule_id":"Brute_Force_Attempt",
"name":"Brute Force Attempt",
"description":"Detects multiple failed login attempts.",
"risk_score":35,
"severity":"medium",
"type":"threshold",
"index":["apm-*-transaction*", "auditbeat-*", "endgame-*", "filebeat-*", "logs-*", "packetbeat-*", "traces-apm*", "winlogbeat-*", "-*elastic-cloud-logs-*"],
"language":"kuery",
"query":"event.code : "4625"",
"threshold":{"field":["user.name"],"value":5,
"interval":"10m",
"from":"now-10m",
"actions":[{"group":"default",
"id":"elastic-cloud-email",
"action_type_id":".email",
"params":{"to":["jycybersec@gmail.com"],
"subject":"Brute Force Attempt",
"message":"Rule {{context.rule.name}} generated {{state.signals_count}} alerts"}}]}
```
### Manual Setup
![image](https://github.com/user-attachments/assets/f17d6482-a655-4480-b8fb-fe179119abeb)

![image](https://github.com/user-attachments/assets/dcc42ceb-4b85-43cd-89e9-29e171ca1933)

![image](https://github.com/user-attachments/assets/c21a2b2e-907f-4264-89d0-4341bb543be5)

![image](https://github.com/user-attachments/assets/0cf62676-d148-4927-9ecd-6df86d04aab0)

![image](https://github.com/user-attachments/assets/1cd50c6f-663d-45ec-b0c4-b3e619724146)

![image](https://github.com/user-attachments/assets/af4ed663-5024-4dc1-ac46-3ec9f7a9f846)


### 2. Malicious process execution
- **Rule**: Detect a variety of Malicous Process Arguments.
- **Condition**: Malicous process is executed.
- **Trigger**: Monitor process logs for matching arguments.
- **Detection Rule**: 
```JSON
{"rule_id":"Malicious_Process_Execution",
"name":"Malicious Process Execution",
"description":"Detects a variety of known malicious process executions.",
"risk_score":43,
"severity":"medium",
"type":"query",
"index":["apm-*-transaction*", "auditbeat-*", "endgame-*", "filebeat-*", "logs-*", "packetbeat-*", "traces-apm*", "winlogbeat-*", "-*elastic-cloud-logs-*"],
"language":"kuery",
"query": "process.args: *nmap* or process.args: *ncrack* or process.args: *mimikatz* or process.command_line.text: "*powershell.exe -ExecutionPolicy Bypass -File*" or process.command_line.text: "*cmd.exe /c*" or process.args: *wmic* or process.args: *mshta* or process.command_line.text: "*bitsadmin /transfer*" or process.command_line.text: "*certutil -urlcache*" or process.command_line.text: "*rundll32.exe javascript:*" or process.command_line.text: "*regsvr32 /s /n /u /i:*" or process.command_line.text: "*msbuild.exe /p:*" or process.command_line.text: "*schtasks /run /tn*" or process.args: *agenttesla* or process.args: *azorult* or process.args: *formbook* or process.args: *ursnif* or process.args: *lokibot* or process.args: *nanocore* or process.args: *qakbot* or process.args: *remcos* or process.args: *trickbot* or process.args: *gootloader* or process.args: *magiclantern* or process.args: *finfisher* or process.args: *warriorpride* or process.args: *netbus* or process.args: *beast* or process.args: *blackhole* or process.args: *gh0strat* or process.args: *tinybanker* or process.args: *clickbot* or process.args: *zeus* or process.args: *shedun*",
"interval":"5m",
"from":"now-1m",
"actions":[{"group":"default",
"id":"elastic-cloud-email",
"action_type_id":".email",
"params":{"to":["jycybersec@gmail.com"],
"subject":"Malicious Process Execution",
"message":"Rule {{context.rule.name}} generated {{state.signals_count}} alerts"}}]}
```
![image](https://github.com/user-attachments/assets/90536a70-303b-4635-866f-aaf12746ba2b)


### 3. Uncommon Directory File Execution
- **Rule**: Alert on execution of files from uncommon directories.
- **Condition**: Any `process.start` event where the file path is outside of standard directories.
- **Trigger**: Look for process execution logs with `event.action:process_start` and `file.path:/tmp/*`.
- **Detection Rule**:
```JSON
{"rule_id":"uncommon_directory_file_execution",
"name":"Suspicious File Execution",
"description":"Detects process start events from suspicious file paths.",
"type":"query",
"index":["apm-*-transaction*", "auditbeat-*", "endgame-*", "filebeat-*", "logs-*", "packetbeat-*", "traces-apm*", "winlogbeat-*", "-*elastic-cloud-logs-*"],
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
![image](https://github.com/user-attachments/assets/ccbbf7bd-eeb1-4568-b57c-6fa8cefe179c)


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
"index":["apm-*-transaction*", "auditbeat-*", "endgame-*", "filebeat-*", "logs-*", "packetbeat-*", "traces-apm*", "winlogbeat-*", "-*elastic-cloud-logs-*"],
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
![image](https://github.com/user-attachments/assets/c3502b35-38e4-46f3-bf04-a59c6e639224)


## Attack Simulation

### 1. Brute Force Attempt
- **Technique**: Brute force SMB login using Metasploit Framework.
- Agent: windows11
- Attacker: Kali Linux

Pass.txt File Creation
![image](https://github.com/user-attachments/assets/962f5cd9-84d3-49e1-9798-7d0a073b8679)

SMB Brute Force Attack
![image](https://github.com/user-attachments/assets/0390426c-d565-4359-9d4c-87277edef44d)

Alert
![image](https://github.com/user-attachments/assets/59a09334-6061-4b10-9820-9b6591f99998)


### 2. Malicious Process Execution
- **Technique**: Perform an Nmap port/service enumeration and a certutility command to extract url cache.
- Agent: windows10

Certutil -urlcache Extraction
![image](https://github.com/user-attachments/assets/f72e17ee-a3c1-463b-9396-32aac5f6cb02)

- Agent: purplesec

Nmap -sT -A 10.0.2.15 (TCP Connect with Agressive Scan) to reveil open ports and OS information
![image](https://github.com/user-attachments/assets/b147a949-6a56-4acc-9bd9-cb95de9cead2)

Alert
![image](https://github.com/user-attachments/assets/18888920-b2cf-4ad4-a516-937a6a679f5a)


### 3. Uncommon Directory File Execution
- **Technique**: Execution of malware payload from a temporary directory or user profile.

Malware Payload
![image](https://github.com/user-attachments/assets/c6548873-59e2-4cd6-9af6-84d760e1e835)

File Creation, Modification, and Execuiton
![image](https://github.com/user-attachments/assets/84483d04-7f0d-4287-bcbb-89df62d68419)

Alert
![image](https://github.com/user-attachments/assets/bde38980-3ac3-4a8b-bf28-db10a1e42168)


### 4. Data Exfiltration Attempts
- **Technique**: Exfiltration of data using a file transfer service.
- Agent: windows10
- Recipient: Kali Linux

Kali External IP
![image](https://github.com/user-attachments/assets/6198bf3d-f3cd-4a58-8895-be43ce0cf789)

Sensitive.txt 600 MB File Creation
![image](https://github.com/user-attachments/assets/13078d09-0d26-404a-af72-43e1d7c1990d)

SCP File Transfer
![image](https://github.com/user-attachments/assets/b28e7e37-a828-4977-a401-a6bb6d00964e)

Received FIle
![image](https://github.com/user-attachments/assets/53ed0e95-78a1-4e75-a9ed-11d48942e563)

Alert
![image](https://github.com/user-attachments/assets/aac322ae-4460-464e-962a-768f744bc627)


## Mitigation Strategies

### 1. Brute Foce Attempt
- **Mitigation**: Implement account lockout policies and monitor for repeated authentication failures.

### 2. Malicious Process Execution
- **Mitigation**: Implement application whitelisting, monitor process creation events, and use endpoint detection and response (EDR) solutions to detect and block malicious processes.

### 3. Uncommon Directory File Execution
- **Mitigation**: Restrict execution from non-standard directories and monitor process creation events.

### 4. Data Exfiltration Attempts
- **Mitigation**: Monitor for large outbound transfers and any use of compression or encryption tools not typically used.
