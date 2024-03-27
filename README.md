<h1> DFIR Lab with Muitilple Tools</h1>

<h2>Description</h2>
In the outlined Digital Forensics and Incident Response (DFIR) lab exercise, the methodology starts with the acquisition of three virus samples from VirusTotal. Following this initial step, the Process Hacker tool is employed for detailed analysis. Wireshark is also used as an export of a PCAP file, succeeded by the use of FTK Imager for capturing a memory dump file. The lab then incorporates Wireshark for the examination of unusual network activity and Volatility for scanning and identifying any rogue processes that indicate malware activity. A subsequent phase involves performing a string analysis on the malicious image file, aiming to support the development of YARA rules. The exercise concludes with deploying Thor Lite to scan the system once more, testing the efficiency and accuracy of the newly formulated YARA rules. This description highlights the  steps involved in a DFIR lab exercise, focusing on the tools and processes for effective malware analysis and detection.
  
<br />


<h2>Tools or Utilities Used</h2>

- <b>Process Hacker</b> 
- <b>Wireshark</b>
- <b>AccessData FTK Imager 4.3.0.18</b>
- <b>Volatility 3</b>
- <b>Strings</b>
- <b>Thor Lite ver. 10.7.4 </b>
- <b>VirusTotal website</b>


<h2>Environments Used </h2>

- <b>Kali Linux 2023.1</b>
- <b>Windows 10 VM</b> 
- <b>VMware Workstation 17 Pro</b> 

<h2>Infection simulation walk-through:</h2>

<p align="center">
First, go to the VExchange · Virus. exchange website and download any 3 malware to the Windows VM machine. Windows security settings have been changed so that there is an exclusion folder where it holds the malware before the OS system deletes it. Later, I also turned off all the firewall and security settings on the machine to ensure the test would work. <br/>
  
<img src="https://imgur.com/i0gLE29.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
Then, execute the five malware samples with administrator privileges. Continue until a ransom note becomes visible.  <br/>
  
<img src="https://imgur.com/cRQiJK1.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
After executing the malware samples with administrator rights, one of the malware triggers a ransom note and transforms all my folders into icons with lock symbols, indicating they have been encrypted. Both Process Hacker and Wireshark reveal that several .exe files are operating in the background, with some attempting to establish connections to remote locations. <br/>
  
<img src="https://imgur.com/j9QPPfD.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
I activated the VM's network sharing feature to transfer files to another platform for more detailed examination.  <br/>
  
<img src="https://imgur.com/ecPXjhx.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
As soon as the ransom note from the malware was displayed, I halted Wireshark's packet capturing. Thanks to the shared folder feature enabled between my virtual machine (VM) and my host machine, I managed to save the pcap file before the malware caused my VM to crash.  <br/>
  
<img src="https://imgur.com/vhsaW7c.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
Employ FTK Imager to perform a memory dump. After completing the dump process, do not close the application. Instead, start transferring the memory dump file from the VM to the host machine.  <br/>
  
<img src="https://imgur.com/NJ9NMbI.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
</p>

<h2>Start analysing with Volatility on Kali:</h2>

<p align="center">
I transferred the memory file from my host machine to a custom folder on the Kali VM machine to proceed with the next steps.<br/>
  
<img src="https://imgur.com/GGrXmko.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
I discovered that Volatility 3 is already installed on my Kali VM, as indicated by the system's response when I attempted to repeat the installation commands, confirming its presence.<br/>
  
<img src="https://imgur.com/cKsnG7t.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
Now is the moment to deploy Volatility to scrutinize the memory file. By executing this command alongside the plugin "windows.pslist.PsList," we can unveil all the application processes that were active on the infected PC prior to capture. The resulting list might be extensive, reflecting the number of files that were operational beforehand. While I haven't documented every detail here, I meticulously reviewed the entire list, marking the processes deemed suspicious with yellow highlights to simplify identification.<br/>
  
<img src="https://imgur.com/srF8yhK.png" height="80%" width="80%" alt="DFIR Steps"/>
<img src="https://imgur.com/7PQSvAN.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
I cataloged all the suspicious Process IDs (PIDs) and tried to gather more information using the "windows.dumpfiles" command. Unfortunately, I encountered issues with PIDs 39156 and 39908, from which I couldn't retrieve any data. However, the command worked successfully for PID 6316, which is associated with the executable file "gbQfH.exe," allowing me to list out all its details comprehensively.<br/>
  
<img src="https://imgur.com/iWev700.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
After executing the command, I successfully located the suspected malware executable file, now in image format, within the Volatility 3 folder.<br/>
  
<img src="https://imgur.com/DFB2FoH.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
I transferred the image file to a different folder and eliminated the extraneous parts of the file name to streamline the process for further investigation in the subsequent steps.<br/>
  
<img src="https://imgur.com/M3XuPmY.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
After executing the "windows.netscan.NetScan" command, it revealed all the network connections present in the memory dump. Interestingly, there was no direct mention of the malwares in question. This suggests that they might be disguising their network connections under different file forms or possibly leveraging legitimate Windows service files like "winslogon.exe" for internet connectivity. Additionally, the data retrieved with the netstat plugin in Volatility reflects the network connections and running processes at the time of the memory dump. It's important to note that this snapshot might not align perfectly with the historical network traffic recorded in the pcap file, as the latter documents past communications between network entities.<br/>
  
<img src="https://imgur.com/zCmPjKf.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
After entering the "windows.netstat" command, I observed that only a fragment of the network status and protocol statistics was displayed, likely due to certain limitations. Research on GitHub suggested that these issues might stem from the inability to fully accommodate the symbol table from the latest version of Windows. Consequently, the reliability of these results is questionable. Upon further investigation of the IP addresses on VirusTotal, they all appeared to be legitimate destinations associated with Windows services.<br/>
<img src="https://imgur.com/jE6ZnMY.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
However, since Volatility revealed the presence of the three malwares we downloaded using a different command, it's plausible that traces of their activity could be found in Wireshark. An example of this is a DNS query for the domain "loki-locker.one" originating from my IP address, 192.168.10.146. This particular activity aligns with the ransomware note observed on the desktop of my Windows VM, indicating that the malware attempted to establish a connection to its command and control server via the malware's cloud URL index page. This serves as evidence that the malware was actively trying to communicate with an external server.<br/>
<img src="https://imgur.com/GIZJVYU.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
Another intriguing discovery emerged from analyzing the Wireshark data. Upon examining the DNS query records, it was interesting to note that the infected machine attempted to connect to Spotify-related subdomain addresses. Further investigation into this activity revealed that the IP address 35.186.224.25 was involved in initiating the TCP handshake process, as well as in the exchange of certificates and cipher keys. This detail adds layer of complexity to the investigation, suggesting that the malware might have been trying to disguise its communication by mimicking traffic to well-known services.
<br/>
<img src="https://imgur.com/mjWhuYm.png" height="80%" width="80%" alt="DFIR Steps"/>
<img src="https://imgur.com/3twjVhK.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
Upon consulting VirusTotal and reviewing comments there, it was noted that the activity involving the Spotify subdomain addresses is associated with a Spotify brute force attack. However, the specific root malware responsible for initiating this activity remains uncertain. The connection to Spotify indicates a potential attempt to exploit or test credentials, yet pinpointing which of the initially downloaded malwares is behind this action requires further analysis. This ambiguity highlights the complexity of malware behavior and the challenges in tracing specific actions back to their origins in cybersecurity investigations.
<br/>
<img src="https://imgur.com/tFeIgN0.png" height="80%" width="80%" alt="DFIR Steps"/>
<img src="https://imgur.com/CgCj7eS.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
</p>


<h2>Performing strings analysis for the development of Yara signature rules and further testing with Thor Lite:</h2>

<p align="center">
In this lab, where multiple malware samples were tested, the next steps involve utilizing the `strings` command to extract all readable character sequences from the target files previously identified with Volatility. The first file in question is named `CXYIJlo.exe`, which is one of the malware samples under investigation. The second file pertains to what is referred to as "ebc" malware. Upon investigating the hash of this file, it appears to be associated with the Loki ransomware, indicating its likely purpose and functionality. The final analysis focuses on a file named `gbQfH.exe`, which is another malware sample selected for examination. Through these steps, the aim is to uncover more about the nature, capabilities, and potential origins of each malware sample by analyzing the strings extracted from their respective files.<br/>
  
<img src="https://imgur.com/h3gxbwO.png" height="80%" width="80%" alt="DFIR Steps"/>
<img src="https://imgur.com/draqr3n.png" height="80%" width="80%" alt="DFIR Steps"/>
<img src="https://imgur.com/HnIbUP9.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
To enhance the identification and analysis of the malicious processes dumped during the lab, Yara rules are crafted for each one. This approach involves using the `strings` data extracted from the malware samples to define patterns unique to each malware variant. After analyzing the strings, a Yara rule is specifically created for the Loki ransomware. This rule is structured such that for a positive identification to be reported by the virus scanner, two specific strings identified in the Loki ransomware's dumped process must be matched simultaneously. This condition ensures a more accurate detection by requiring multiple indicators of compromise (IOCs) to be present, reducing the likelihood of false positives. The created Yara rules are then tested against the dumped processes using the custom signatures feature of Thor Lite, a tool designed for advanced malware detection and analysis. This process not only validates the effectiveness of the Yara rules but also enhances the overall security posture by enabling the detection of sophisticated threats.
<img src="https://imgur.com/JfDy59Y.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
For the second Yara rule, which is dedicated to identifying the CXY malware, an alternative approach is adopted in defining the condition for detection. In addition to the option of specifying that "2 of them" strings need to match for a report to be generated, the rule allows for the explicit naming of "string 1" and "string 2". This means that for a detection to be flagged, both of these specified strings must be found within a scanned file or process simultaneously. This method enhances the specificity of the Yara rule, ensuring that only processes containing both strings are identified as instances of the CXY malware.

<img src="https://imgur.com/zoIxq1F.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
For the third Yara rule, tailored for the Gbq malware, the detection condition is designed to enhance precision by requiring a match for "3 of them" specified strings within the target. This approach further refines the detection process by ensuring that only entities containing all three identified strings are flagged, significantly reducing the chances of false positives.

<img src="https://imgur.com/t1VEkH8.png" height="80%" width="80%" alt="DFIR Steps"/>

<br />
<br />
To ensure Thor Lite effectively utilizes these newly created Yara rules for malware detection, it's essential to place the Yara rule files into the "custom-signatures" folder. This folder is located within the directory "thor10.7lite-linux-pack." Proper placement of the Yara files is a critical step to integrate them with Thor Lite's scanning capabilities, allowing for the execution of these custom rules during the malware search process. This integration enables Thor Lite to leverage the specific criteria defined in the Yara rules for more targeted and accurate malware identification and analysis.
<br />
<br />
After transferring the Thor Lite file folder for semester 2 to the Kali machine and incorporating the license into said folder, the command to initiate a scan of the entire folder utilizing the custom Yara rule files I've created is executed as follows: `./thor-lite-linux -p <folder path>`. This command instructs Thor Lite to perform a comprehensive scan of the specified folder path, applying the Yara rules I've developed to identify any malware that matches the criteria outlined in those rules. This process allows for a targeted search within the folder, leveraging the precision of the Yara rules to detect and analyze potential malware threats effectively.

<img src="https://imgur.com/g8kxffw.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
The screenshots show that the three Yara rule files matched the findings in the target folder, successfully identifying the malware image files. This outcome indicates that the rules were precisely crafted and applied effectively, enabling the detection of malware based on the specified criteria. The success of this action highlights the effectiveness of using custom Yara rules for targeted malware detection and analysis.

<img src="https://imgur.com/38FV0kM.png" height="80%" width="80%" alt="DFIR Steps"/>
<img src="https://imgur.com/mf5nn8h.png" height="80%" width="80%" alt="DFIR Steps"/>
<br />
<br />
</p>

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
