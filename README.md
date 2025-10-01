# 🛡️SOC-Automation-Project-Wazuh-Shuffle-TheHive
## 📌 Project Overview
This project demonstrates the design and deployment of a small **Security Operations Center (SOC) automation lab** using open-source tools. The objectives are to:
- Establish **centralized log collection and detection** with **Wazuh**
- Generate **high-fidelity endpoint telemetry** with **Sysmon**
- Integrate **automated incident case management** with **TheHive**

## 🧩 Project Parts
1. **Deploy** the Wazuh stack and TheHive servers  
2. **Enroll** a Windows endpoint in Wazuh and set up TheHive organizations  
3. **Install** Sysmon with a community-tuned configuration and forward logs to Wazuh  
4. **Automate** alert forwarding from Wazuh to TheHive to create incident cases

## 🧰 Core Components
- **Windows 10/11 client (Sysmon + Wazuh Agent):** Generates security telemetry (process starts, hashes). The Wazuh Agent ships normalized events to the Manager.  
- **Wazuh Platform:** Manager evaluates rules and creates alerts. Indexer stores events for search. Dashboard provides the web UI. Wazuh forwards selected alerts to **Shuffle** via webhook.  
- **Shuffle SOAR (Cloud):** Receives Wazuh alerts, extracts indicators with **Regex**, enriches with **VirusTotal**, and calls **TheHive API** to create alerts. Can send email or chat notifications.  
- **TheHive:** Central alert/case management—stores alerts, tasks, observables, and analyst notes.  
- **Email service:** Used by Shuffle to notify the SOC analyst.  
- **SOC Analyst workstation:** Receives notifications, opens TheHive, and handles triage.
## 🔁 Data Flow (High Level
![## 🔁 Data Flow (High Level)](https://raw.githubusercontent.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/d753c8f02135372f02047a6ebbc27c3757df1623/assets/Screenshot%202025-08-25%20143602.png)
---
## 🖥️ Step 1 & Step 2: Server Setup and Windows Agent Deployment
##  1.Server Setup 

In **Vultr**, I created:  
- **Wazuh server** → 4 vCPU / 8 GB RAM, Ubuntu LTS  
- **TheHive server** → 6 vCPU / 16 GB RAM, Ubuntu LTS  

💻 On the **Wazuh server**, I:  
- Installed Wazuh (all-in-one: Manager + Indexer + Dashboard).  
- Allowed HTTPS access with UFW:  

bash
sudo ufw allow 443/tcp
Logged in to the Wazuh Dashboard using the public IP.

🐝 On the TheHive server, I:

Installed TheHive and all required components.

Allowed UI/API port with UFW:

bash
Copy code
sudo ufw allow 9000/tcp
Logged in to TheHive using the browser.
![server)](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/6824cb4652215d9892a1dde3e53ded04149163d2/assets/Screenshot%202025-09-27%20113207.png)





## 2.Windows Agent Deployment
🪟 From the Wazuh Dashboard → Agents → Deploy new agent, I selected Windows as the OS, entered my Windows VM’s hostname/IP, and copied the one-liner PowerShell command provided.

On my Windows 11 VM, I ran this command in PowerShell (Administrator), which downloaded and installed the agent, auto-registering it with the Wazuh Manager.

🔒 Back on the Wazuh server, I opened the required agent communication ports:

sudo ufw allow 1515/tcp   # agent registration
sudo ufw allow 1514/udp   # agent events


✅ Finally, I refreshed the Wazuh Dashboard and saw the Windows agent appear as Active (green), confirming it was successfully registered and sending logs.

![Wazuh manager](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/85862c8cdf55aeb576f4b2293579a2f62066a391/assets/Screenshot%202025-09-27%20171436.png)
---

## 🖥️ Step 3: Sysmon Ingestion + Mimikatz Detection  

Now configuring the Windows 11 virtual machine and start sending the Sysmon telemetry over to the Wazuh manager, then I am creating the custom detection rule looking for mimikatz activity.

### Configure Windows 11 VM and install Sysmon & Wazuh Agent  
On the Windows 11 VM I installed Sysmon (community config) and the Wazuh Agent. I ran the Wazuh agent installer in an elevated PowerShell so the agent auto-registered with the Wazuh manager.

PowerShell (Administrator) example (run on Windows 11 VM):
powershell
 install Sysmon with community config (example)
.\Sysmon64.exe -i .\sysmonconfig-export.xml -accepteula

### install Wazuh agent 
(replace <one-liner> with the command you copied from the dashboard)
powershell -ExecutionPolicy Bypass -Command "<one-liner-from-wazuh-dashboard>"
Backup ossec.conf on Wazuh manager
On the Wazuh manager I created a timestamped backup of ossec.conf before editing.

sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf
ls -l /var/ossec/etc/ossec.conf*
### Add Sysmon EventChannel ingestion to ossec.conf
I opened /var/ossec/etc/ossec.conf and added a localfile block to collect the Sysmon EventChannel.

Edit on Wazuh manager:

sudo nano /var/ossec/etc/ossec.conf


Insert inside the <localfile> / log analysis section:
![screenshot](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/591300e55a0c3c6fb807cccfa0c5c75cdb91214f/assets/Screenshot%202025-09-27%20172349.png)

### Confirm Sysmon events appear in Wazuh Explorer
I verified the Windows endpoint is sending Sysmon events and that they are visible in Wazuh Explorer / archives.

### Generate test Mimikatz telemetry on Windows VM
I downloaded mimikatz_trunk.zip from GitHub (lab only), extracted it, and executed mimikatz.exe in an elevated PowerShell to produce Sysmon telemetry.


### No alerts created a custom local rule
When no alert appeared, I created (or updated) /var/ossec/etc/rules/local_rules.xml with a rule matching the observed Sysmon fields (Image/CommandLine).
I created /var/ossec/etc/rules/local_rules.xml with a PCRE/regex that matches mimikatz.exe.

![screenshot](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/e99bd7a9a623872a80f992999cce5878ae935efb/assets/image.png)

### Restart Wazuh manager and re-run Mimikatz
I restarted the manager, then re-executed mimikatz.exe on the Windows VM to trigger the rule.

![screenshot](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/c8f810f2d14b67594691c557f77de4d09707aa8a/assets/Screenshot%202025-09-28%20103313.png)

### Confirm alert in Wazuh Alerts
After the re-run, the local rule matched and an alert appeared in Wazuh Alerts titled "Mimikatz usage detected". I verified alert details on the manager.
![screenshot](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/0674cd3a6957f1c4523f7ae02ef60bd553cad251/assets/Screenshot%202025-09-27%20180202.png)

---

## 🖥️Step 4 & Step 5: Shuffle.io automation (Webhook → SHA256 → VirusTotal → TheHive)

**Two main steps** (git friendly):  
Build the Shuffle workflow and node configurations. 🧩  
 Test the workflow, troubleshoot VT "resource not found", connect TheHive, and capture screenshots. 🔎✅

## Step 4  Build the Shuffle workflow (Webhook listener + SHA256 extractor + VT + TheHive) 🧩

###  Create a webhook trigger node
- **Name:** `Webhook-Alert`  
- **Method:** POST  
- **Path / URL:** Shuffle will give you a public webhook URL (e.g. `https://<shuffle-host>/webhook/<id>`)  
- **Purpose:** receive Wazuh alert JSON when rule id `100002` is fired.

> Example webhook payload snippet (Wazuh JSON):
json
{
  "rule_id": "100002",
  "title": "Mimikatz Usage Detected",
  "text": {
    "win": {
      "system": {...},
      "eventdata": {
         "hashes": "SHA256=61c0810a23580cf492a6ba4f7654566b...;MD5=..."
      }
    }
  },
  "_all_fields": {...}
}
Save this snippet for testing in the Regex node.

![Screenshot](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/bfbfeacf8c969aa5d8ad7cca89fefc9dfbe63c90/assets/image.png)

### Add a Regex capture group node (extract SHA256) 🔍
Name: SHA256-Hash

Input data: $exec.all_fields.data.win.eventdata.hashes
(or the exact JSON path to your hashes field; the screenshot shows $exec.all_fields.data.win.eventdata.hashes)

Regex: SHA256=([0-9A-Fa-f]{64})

This captures only the 64-char SHA256 hex string (first capture group).

Output: group_0 or capture[0] depending on Shuffle node naming — verify node output when you run it.

If your hashes field sometimes comes with no SHA256= prefix, use a more flexible regex:

ruby
Copy code
(?:SHA256=)?([0-9A-Fa-f]{64})
Why: VirusTotal expects the raw hash (no SHA256=). If the node sends SHA256=... VT will return "resource not found". Strip the prefix via regex.

![Screenshot](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/bd7a267380c82254692d125d687552fdfe96474b/assets/Screenshot%202025-09-28%20120753.png)

### Add a VirusTotal node (v3 file lookup) 🧾
Name: VirusTotal-v3

Action: File report (GET /api/v3/files/{id})

Input: the captured SHA256 from previous node (e.g. {{SHA256-Hash.group_0}} or {{exec_regex_group[0]}})

Auth: x-apikey: <YOUR_VT_API_KEY> or as Shuffle VT app config depending on how you configured apps.

Expected response: HTTP 200 with data.id and attributes if a record exists. If VT returns 404 or message resource not found then check captured string (no prefix, correct length).

Common pitfall: Sending SHA256=61... instead of 61... will return "resource not found". Used regex above to extract clean hash.

![Screenshot](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/7913ad97b907bca3880aff55ac64614cdce1af13/assets/Screenshot%202025-09-28%20121639.png)

###  Add TheHive HTTP / JSON node (create case) 🐝
Name: Create-TheHive-Case

Method: POST

URL: http://<THEHIVE_HOST>:9000/api/case

Headers:

Authorization: Bearer <THEHIVE_APIKEY>

Content-Type: application/json



json
Copy code
{
  "description": "{{exec.title}} - automated Wazuh alert",
  "externalLink": "{{exec.externalLink}}",
  "flag": false,
  "pap": 2,
  "severity": "{{exec.severity}}",
  "source": "{{exec.pretext}}",
  "sourceRef": "{{exec.rule_id}}",
  "status": "New",
  "summary": "Mimikatz activity detected on host {{exec.text.win.system.computer}}",
  "tags": ["T1003"],
  "title": "{{exec.title}}",
  "tlp": "2",
  "type": "internal",
  "artifacts": [
    {"dataType": "file", "data": "{{SHA256-Hash.group_0}}"},
    {"dataType": "string", "data": "{{exec.text.win.eventdata.Image}}"}
  ]
}

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

### Step 7 — Add Email node, configure recipient, re-run and verify email (📧)
- Action: In Shuffle workflow add an **Email** node or update existing Email node:
 - Gave the email address 
- Connected Email node after TheHive node (or use TheHive response to include created case id/link).
- Re-run the workflow.
- Verified inbox for email from Shuffle Email App with the subject and description.

![Screenshot](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/58b524e8bd900f6ab129f9dc4598c8a3d6033849/assets/Screenshot%202025-09-28%20145753.png)
![Screenshot](https://github.com/addula-mounika12/-SOC-Automation-Project-Wazuh-Shuffle-TheHive/blob/ea6a9eae7b67b035bca45a7a69c899fe3bed3bd5/assets/Screenshot%202025-09-29%20084901.png)

