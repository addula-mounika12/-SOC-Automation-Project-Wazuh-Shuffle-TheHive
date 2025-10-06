# 🛡️ SOC Automation Project — Wazuh | Shuffle | TheHive

## 📌 Project Overview
This project demonstrates the design and deployment of a small-scale **Security Operations Center (SOC) automation lab** using open-source tools.  
The goal is to simulate a real-world SOC environment by integrating **SIEM**, **SOAR**, and **incident management** solutions to automate detection, enrichment, and response processes.

---

## 🎯 Objectives
- Establish centralized log collection and detection using **Wazuh**  
- Generate detailed endpoint telemetry with **Sysmon**  
- Automate incident creation and case management with **TheHive** through **Shuffle SOAR**

---

## 🧩 Project Components
- **Windows 10/11 Client (Sysmon + Wazuh Agent):** Generates security telemetry (process starts, file hashes) and forwards events to the Wazuh Manager.  
- **Wazuh Platform:** Performs rule evaluation, creates alerts, stores indexed events, and forwards selected alerts to Shuffle via webhook.  
- **Shuffle SOAR (Cloud):** Receives alerts, extracts indicators (e.g., SHA256), enriches data via VirusTotal, and automatically creates cases in TheHive.  
- **TheHive:** Manages alert ingestion, incident tracking, observables, and analyst workflows.  
- **Email Service:** Used by Shuffle to notify SOC analysts.  
- **SOC Analyst Workstation:** Receives alerts, reviews cases in TheHive, and performs triage.

---

## 🔁 Data Flow (High Level
![## 🔁 Data Flow (High Level)](https://raw.githubusercontent.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/d753c8f02135372f02047a6ebbc27c3757df1623/assets/Screenshot%202025-08-25%20143602.png)
---
## 🖥️ Step 1 & Step 2: Server Setup and Windows Agent Deployment

### 1️⃣ Server Setup
Deployed two servers on **Vultr Cloud**:
- **Wazuh Server:** 4 vCPUs / 8 GB RAM (Ubuntu LTS)
- **TheHive Server:** 6 vCPUs / 16 GB RAM (Ubuntu LTS)

#### On the Wazuh server:
bash
# Install Wazuh (All-in-One: Manager + Indexer + Dashboard)
sudo ufw allow 443/tcp  # Allow HTTPS access
Logged into the Wazuh Dashboard using the public IP.

On the TheHive server:
bash
Copy code
sudo ufw allow 9000/tcp  # Allow UI/API access
Installed TheHive and verified successful login through the web interface.

![server)](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/6824cb4652215d9892a1dde3e53ded04149163d2/assets/Screenshot%202025-09-27%20113207.png)




2️⃣ Windows Agent Deployment
From the Wazuh Dashboard → Agents → Deploy new agent, selected Windows as the OS and copied the generated PowerShell one-liner.

On the Windows 11 VM (run as Administrator):

powershell
Copy code
powershell -ExecutionPolicy Bypass -Command "<one-liner-from-wazuh-dashboard>"
Opened the required agent communication ports:

bash
Copy code
sudo ufw allow 1515/tcp   # Agent registration  
sudo ufw allow 1514/udp   # Agent events  
✅ Verified the agent status as Active (green) in the Wazuh Dashboard.

![Wazuh manager](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/85862c8cdf55aeb576f4b2293579a2f62066a391/assets/Screenshot%202025-09-27%20171436.png)
---

## 🧠 Step 3: Sysmon Ingestion and Mimikatz Detection
Sysmon Installation & Configuration
On the Windows 11 VM:

powershell
Copy code
# Install Sysmon with the community configuration
.\Sysmon64.exe -i .\sysmonconfig-export.xml -accepteula
Reinstalled the Wazuh agent (Administrator mode) to ensure telemetry forwarding.

Update Wazuh Manager Configuration:
bash
Copy code
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.backup
sudo nano /var/ossec/etc/ossec.conf
Added Sysmon EventChannel ingestion inside <localfile> tags.



Confirmed Sysmon telemetry appeared under Wazuh Explorer → Archives.

Mimikatz Detection Test
Executed mimikatz.exe (lab-only) to generate Sysmon events.
No alert appeared initially, so created a custom rule in:

bash
Copy code
sudo nano /var/ossec/etc/rules/local_rules.xml
Added a regex rule to detect Mimikatz process execution.



Restarted Wazuh Manager:

bash
Copy code
sudo systemctl restart wazuh-manager
Re-ran Mimikatz and confirmed alert titled “Mimikatz Usage Detected” appeared in Wazuh Alerts.
I restarted the manager, then re-executed mimikatz.exe on the Windows VM to trigger the rule.

![screenshot](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/0674cd3a6957f1c4523f7ae02ef60bd553cad251/assets/Screenshot%202025-09-27%20180202.png)

---

## ⚙️ Step 4 & Step 5: Shuffle SOAR Automation (Webhook → Regex → VirusTotal → TheHive)
1️⃣ Webhook Trigger Node
Configured a webhook trigger in Shuffle to receive Wazuh alerts for rule ID 100002.

Example Payload:

json
Copy code
{
  "rule_id": "100002",
  "title": "Mimikatz Usage Detected",
  "text": {
    "win": {
      "eventdata": {
         "hashes": "SHA256=61c0810a23580cf492a6ba4f7654566b...;MD5=..."
      }
    }
  }
}


2️⃣ Regex Extraction Node
Extract SHA256 hash from alert:

ini
Copy code
SHA256=([0-9A-Fa-f]{64})
✅ Ensures VirusTotal receives a clean hash (without SHA256= prefix).



3️⃣ VirusTotal Node
Action: File report (GET /api/v3/files/{id})

Input: Captured SHA256

Auth: API key or pre-configured Shuffle app

Handles “resource not found” errors automatically.



4️⃣ TheHive Case Creation Node
Method: POST
URL: http://<THEHIVE_HOST>:9000/api/case
Headers:

pgsql
Copy code
Authorization: Bearer <THEHIVE_APIKEY>
Content-Type: application/json
Example Payload:

json
Copy code
{
  "description": "{{exec.title}} - automated Wazuh alert",
  "summary": "Mimikatz activity detected on host {{exec.text.win.system.computer}}",
  "source": "Wazuh",
  "sourceRef": "{{exec.rule_id}}",
  "status": "New",
  "severity": "{{exec.severity}}",
  "tags": ["T1003"],
  "title": "{{exec.title}}",
  "artifacts": [
    {"dataType": "file", "data": "{{SHA256-Hash.group_0}}"},
    {"dataType": "string", "data": "{{exec.text.win.eventdata.Image}}"}
  ]
}


![Screenshot](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/bfbfeacf8c969aa5d8ad7cca89fefc9dfbe63c90/assets/image.png)



![Screenshot](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/bd7a267380c82254692d125d687552fdfe96474b/assets/Screenshot%202025-09-28%20120753.png)



![Screenshot](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/7913ad97b907bca3880aff55ac64614cdce1af13/assets/Screenshot%202025-09-28%20121639.png)



![Screenshot](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/81c27b365d41fb8c97d8c5b9b368f54d8c77237e/assets/image.png)

---

### Step 6  Re-run the workflow & verify TheHive case (✔️)
- Action: Re-run the Shuffle run (webhook triggered or re-run via UI).  
- Verified in TheHive (account: **mydma**):
  - Case list shows a new entry titled **"Mimikatz Usage Detected"** (Source: `WAZUH Alert`, Reference `100002`).  
  - Clicked the case → Confirm the **Description** and **Summary** fields are populated (e.g. `Mimikatz Usage Detected` / `Mimikatz activity detected on host mona_pc`).
![Screenshot](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/8a7f01528ff447dbd4b0add07c83f7f3cd95eba1/assets/Screenshot%202025-09-28%20142836.png)
![Screenshot](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/a95436bbd5fb62d17d7d701390f5a6b10f699371/assets/Screenshot%202025-09-28%20142858.png)

---

### Step 7  Add Email node, configure recipient, re-run and verify email (📧)
- Action: In Shuffle workflow add an **Email** node or update existing Email node:
 - Gave the email address 
- Connected Email node after TheHive node (or use TheHive response to include created case id/link).
- Re-run the workflow.
- Verified inbox for email from Shuffle Email App with the subject and description.

![Screenshot](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/58b524e8bd900f6ab129f9dc4598c8a3d6033849/assets/Screenshot%202025-09-28%20145753.png)
![Screenshot](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/ea6a9eae7b67b035bca45a7a69c899fe3bed3bd5/assets/Screenshot%202025-09-29%20084901.png)

