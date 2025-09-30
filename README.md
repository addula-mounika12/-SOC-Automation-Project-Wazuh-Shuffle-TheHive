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

