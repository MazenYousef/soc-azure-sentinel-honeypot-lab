# SOC - Azure Sentinel Honeypot Home Lab

## Description
Cloud SOC home lab on Microsoft Azure: an intentionally exposed VM acts as a honeypot and forwards its logs to Microsoft Sentinel (SIEM). Malicious login attempts are detected with KQL and plotted on an attack map showing where attacks come from. Includes setup steps, queries, screenshots, and lessons learned.


## Overview
This project builds a small Security Operations Center (SOC) environment in the cloud using an Azure free account. A virtual machine is deliberately exposed to the public internet so that real-world attackers find it. The VM is exposed by enabling any inbound traffic on Azure NSG Firewall and disabling Windows Firewall on the VM itself. Its security logs are forwarded to Microsoft Sentinel, where I analyze them with KQL, detect malicious activity, and visualize the geographic origin of the attacks on a map.

**Goal:**  practice the core SOC analyst workflow end to end: collect logs, query them, detect suspicious behavior, and report findings.

## Architecture
<img src="https://i.imgur.com/SerdDep.jpeg" height="80%" width="80%" alt="Disk Sanitization Steps"/>

## Tools and Technologies
| Area | Tool |
|---|---|
| Cloud platform | Microsoft Azure (free account) |
| Honeypot | [Windows / Linux] Virtual Machine with public IP |
| Network control | Azure Network Security Group (NSG) |
| Log collection | Azure Monitor Agent + Data Collection Rule |
| SIEM | Microsoft Sentinel on a Log Analytics workspace |
| Query language | Kusto Query Language (KQL) |
| Visualization | Sentinel Workbook (map) |


## Lab Setup
 
### 1. Prepare the Azure account
- Create an Azure free account.
- **Set a budget alert** before creating anything (Cost Management > Budgets).
- Create a dedicated resource group, for example `rg-honeypot-lab`. Everything in this lab goes into it, so cleanup is one delete.
### 2. Create the honeypot VM
- Create a [Windows 10/11 or Server] VM in the resource group with a public IP address.
- Use a **unique, strong admin password** that you use nowhere else.
- Do not connect the VM to any other network or resource.
### 3. Expose the VM on purpose
- In the VM's NSG, add an inbound rule allowing [any source / any port to any destination / any port] with a high priority.
- Inside the VM, [disable the Windows Defender Firewall] so attackers can reach the services.
- Confirm the VM answers from the internet, for example by pinging its public IP from my own machine.
### 4. Set up Microsoft Sentinel
- Create a Log Analytics workspace in the same resource group.
- Add Microsoft Sentinel to the workspace.
- Open Content hub and install the **Windows Security Events** solution.
- In Data connectors, enable **Windows Security Events via AMA** and create a Data Collection Rule that targets the honeypot VM and collects [All Security Events / Common].
### 5. Verify logs are arriving
In Sentinel > Logs, run:
 
```kusto
SecurityEvent
| take 20
```
 
Rows appearing means the pipeline works. It can take several minutes after the first attacks.


## Detection and Analysis (KQL)
 
The queries below are in [`/queries`](queries/). Windows Event ID **4625** is a failed logon, and **4624** is a successful one.
 
**1. Failed logons by source IP**
 
```kusto
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress
| order by FailedAttempts desc
```
 
**2. Most targeted usernames**
 
```kusto
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by TargetUserName
| order by Attempts desc
| take 20
```
 
**3. Failed logons enriched with location (for the map)**
 
```kusto
SecurityEvent
| where EventID == 4625 and isnotempty(IpAddress)
| extend geo = geo_info_from_ip_address(IpAddress)
| extend Country = tostring(geo.country),
         City = tostring(geo.city),
         Latitude = toreal(geo.latitude),
         Longitude = toreal(geo.longitude)
| summarize FailedAttempts = count() by IpAddress, Country, City, Latitude, Longitude
```
 
**4. Brute-force pattern: 10+ failures from one IP within 5 minutes**
 
```kusto
SecurityEvent
| where EventID == 4625
| summarize Failures = count() by IpAddress, bin(TimeGenerated, 5m)
| where Failures >= 10
| order by Failures desc
```
 
**5. Sanity check: any successful logons that weren't me?**
 
```kusto
SecurityEvent
| where EventID == 4624 and LogonType in (3, 10)
| summarize Logons = count() by IpAddress, TargetUserName
```

## Attack Map
 
- Created a Sentinel **Workbook** with the geo-enriched query (query 3) as its data source.
- Set the visualization to **Map**, using latitude and longitude, with failed-attempt count as the bubble size.
![Attack map](images/attack-map.png)

## Results
 
Observation window: **24 hours**
 
| Metric | Result |
|---|---|
| First failed logon after exposure | 20 mins |
| Total failed logon events | 16000 |
| Unique source IPs | 120 |
| Countries observed | 22 |
| Most targeted usernames | administrator, admin, user, test, guest |
| Successful logons by unknown IPs | 0 |
 
**Observations:** Attacks started within minutes of exposure and came in bursts rather than evenly. A small number of IPs produced most of the volume, and the username lists were dominated by default accounts such as administrator and admin. No attacker achieved a successful logon.

## Skills Demonstrated
 
- SIEM deployment and log onboarding (Microsoft Sentinel, Azure Monitor Agent, Data Collection Rules)
- KQL log analysis and threat detection
- Detection engineering: scheduled analytics rule
- Threat intelligence basics: IP geolocation and MITRE ATT&CK mapping
- Cloud security and network exposure control (NSG)
- Documentation and reporting

---
*Author: Mazen Yousef | [LinkedIn](https://linkedin.com/in/mazenyousef) | [TryHackMe](https://tryhackme.com/p/mazen.yousef)*

