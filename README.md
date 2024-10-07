# SOC Lab for Security Monitoring and Attack Simulation

Firstly, a huge thank you to Eric Capuano for his insightful blog post <a href="https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro">"So you want to be a SOC Analyst?"</a> which served as my guide throughout this project. His expertise and guidance were instrumental in shaping my lab setup. 

## Objective

The SOC Lab project aimed to create a controlled setting for simulating and detecting cyber attacks. The focus was on using real-world security tools to monitor and respond to various attack scenarios, analyzing logs and network traffic to enhance understanding of network security and defensive techniques. This hands-on approach was intended to build practical skills in threat detection and incident response.

### Skills Learned

- Proficiency in using security tools for attack simulation and monitoring.
- Ability to analyze and respond to simulated cyber attacks in real-time.
- Enhanced understanding of network traffic and endpoint behavior.
- Skills in setting up and managing a virtual SOC environment.
- Development of incident response strategies and procedures.

### Tools Used

- Security Information and Event Management (SIEM) system for log collection and analysis.
- Endpoint Detection and Response (EDR) tools for monitoring and managing endpoint activities.
- Network simulation tools for generating and analyzing network traffic and attack scenarios.
- Vulnerability assessment tools for identifying and testing system weaknesses.
- Attack simulation platforms for creating realistic cyber attack scenarios.

## Steps
### <b>STEP 1 - Setting Up a SOC Lab with Windows and Linux VMs, Sysmon, and LimaCharlie</b>
1. System Requirements
- RAM: Minimum 8GB (recommended 16GB+)
- Disk Space: 80-100GB
2. VMware Workstation Pro Setup
- Download and install VMware Workstation Pro (now free for personal use after VMware's acquisition by Broadcom).
- Create a Broadcom account to access download links.
3. Windows VM Setup
- Download the free Windows VM from Microsoft (get the “VMWare” version).
- Unzip the VM and import it into VMware by double-clicking the .ovf file.
- RAM Allocation: Modify to 4GB if your system has ≤ 16GB RAM.
- Expiration Date: Be aware of the expiration date of the VM.
4. Ubuntu Server 22.04.1 VM Setup
- Download the Ubuntu Server 22.04.1 ISO.
- Create a new VM with:
- Disk size: 14GB
- CPU: 2 cores
- RAM: 2GB
- During OS installation, select "Install OpenSSH Server".
- Set a static IP address via VMware Workstation's NAT settings.
5. Disable Windows Defender on Windows VM
- Disable Tamper Protection and all other Defender options.
- Permanently disable Defender via:
- Group Policy Editor
- Registry: Disable all Defender services using regedit.
- Prevent VM Sleep/Standby: Run PowerShell commands to disable hibernate and standby modes.
6. Install Sysmon on Windows VM
- Download and Install Sysmon: <br><br>
 Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Windows\Temp\Sysmon.zip
Expand-Archive -LiteralPath C:\Windows\Temp\Sysmon.zip -DestinationPath C:\Windows\Temp\Sysmon <br><br>
- Download and Use SwiftOnSecurity's Sysmon config: <br><br>
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Windows\Temp\Sysmon\sysmonconfig.xml
C:\Windows\Temp\Sysmon\Sysmon64.exe -accepteula -i C:\Windows\Temp\Sysmon\sysmonconfig.xml <br><br>
7. Install LimaCharlie EDR on Windows VM
- Create a free LimaCharlie account and set up a Windows sensor.
- Download and install the LimaCharlie sensor on the Windows VM using PowerShell.
- Configure Sysmon log shipping to LimaCharlie:
* In LimaCharlie, go to Artifact Collection > Add Rule:
* Name: windows-sysmon-logs
* Path Pattern: wel://Microsoft-Windows-Sysmon/Operational:*
8. Set Up Linux Attacker System
- SSH into the Linux VM from your host system.
- Install Sliver C2 Framework:<br><br>
wget https://github.com/BishopFox/sliver/releases/download/v1.5.34/sliver-server_linux -O /usr/local/bin/sliver-server<br>
chmod +x /usr/local/bin/sliver-server <br>
apt install -y mingw-w64<br>
mkdir -p /opt/sliver<br><br>
9. Explore LimaCharlie Web Interface
- Check out the "Sensors List" in LimaCharlie and explore:
- Timeline
- Processes
- Network
- File System
10. Snapshot VM
Take a snapshot of the clean state of your Windows VM.

### <b>STEP 2 : Generating C2 payload :</b>

1. Access Linux VM and Set Up Sliver
- SSH into the Linux VM, elevate to root, and navigate to the Sliver directory.
- Launch the Sliver server and generate a C2 payload using your Linux VM's IP.
- Confirm the implant configuration in Sliver.
2. Transfer Payload to Windows VM
- Exit Sliver and start a Python HTTP server to serve the payload.
- On the Windows VM, use PowerShell to download the payload from the Linux VM.
3. Snapshot and Execute Payload
- Create a snapshot of the Windows VM labeled "Malware staged."
- Switch back to the Linux VM, stop the Python server, restart Sliver, and enable the HTTP listener.
- Execute the C2 payload on the Windows VM from PowerShell.
4. Manage C2 Session in Sliver
- Verify the session in Sliver and interact with the new C2 session on the Windows VM.
- Run basic commands to gather system info, privileges, working directory, and network connections.
5. Analyze EDR Telemetry in LimaCharlie
- Log into LimaCharlie and select the Windows sensor.
- Explore the process tree, network connections, and file system. Search for the implant and suspicious activities.
- Check the hash of the implant using VirusTotal and review event logs in the timeline to track the implant's actions.

### <b>STEP 3 : Emulating an adversary for crafting detections :</b>

1. Reconnect to C2 Session
- SSH into your Linux VM, launch Sliver, and reconnect to your C2 session on the Windows VM. Make sure you have administrative privileges.
2. Perform Adversarial Action
- Check your privileges to ensure you have "SeDebugPrivilege."
- Dump the lsass.exe process from memory for credential harvesting.
3. Detect Malicious Activity in LimaCharlie
- Switch to the LimaCharlie web interface and filter the timeline of your Windows sensor for "SENSITIVE_PROCESS_ACCESS" events.
- Identify the event related to accessing lsass.exe.
4. Create Detection Rule
- Build a simple detection and response (D&R) rule that triggers when sensitive processes like lsass.exe are accessed.
- Configure the rule to generate an alert when this activity is detected.
5. Test the Detection Rule
- Test the rule against the captured event in LimaCharlie to ensure it detects the lsass.exe access attempt.
- Save and enable the rule.
6. Re-Execute Malicious Action
- Return to your Sliver session and repeat the lsass.exe dump.
- Check the "Detections" tab in LimaCharlie to verify that your custom rule successfully detected the threat.

### <b>STEP 4 : Blocking an attack :</b>

1. Establish a C2 Session
- Connect to your Sliver C2 session on the Windows VM using SSH from the Linux VM.
2. Simulate a Ransomware Action
- In the C2 session, simulate ransomware behavior by triggering the deletion of volume shadow copies, which is a common ransomware tactic.
3. Detect the Activity
- Check LimaCharlie’s detection tab to see if the Sigma rules identified the activity. Examine the metadata in the detection, including reference URLs for additional details.
4. Craft a Blocking Rule
- Use the detection data to create a custom Detection & Response (D&R) rule in LimaCharlie. The rule should generate a report and terminate the parent process responsible for the deletion attempt.
5. Test the Blocking Rule
- Rerun the deletion command and check if the parent process was successfully killed by your new D&R rule. If the system shell hangs or exits, the rule worked.
6. Refine the Rule
- Enhance the rule by using broader pattern matching, such as searching for key terms like “delete” and “shadows” in command lines to account for variations in how ransomware might delete volume shadow copies.

### <b>STEP 5 : Trigger YARA scans with a detection rule :</b>
1. Add YARA Signature for Sliver C2 Payload:

- Access the "YARA Rules" in the LimaCharlie dashboard and create two new YARA rules: one for the Sliver payload and another for Sliver processes.
- Save these rules for future use.
2. Create Detection & Response (D&R) Rules:

- Set up two D&R rules: one for detecting YARA-based file system activity and another for process activity.
- These rules will trigger alerts and tag YARA detections in the system.
3. Test YARA Signature with Manual Scan:

- In the EDR Sensor Console, perform a manual YARA scan on your Sliver payload to ensure the signature is functioning.
4. utomate YARA Scans for New EXE Files:

- reate a rule to detect new .exe files in the Downloads folder.
- Set this rule to trigger a YARA scan on the new files automatically.
5. Automate YARA Scans for Processes:

- Create another rule to detect and scan processes launched from the Downloads folder.
- The rule will automatically scan the process memory for suspicious activity.
6. Trigger the New Rules:

- Simulate moving files into the Downloads folder or launching processes from there.
- Confirm that YARA detects and flags the activity in the "Detections" tab.
7. Monitor for Detections:

- Check the "Detections" tab for alerts on both file system and process activity as YARA scans are triggered.
