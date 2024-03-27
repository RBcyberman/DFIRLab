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


<h2>Performing string analysis for the development of Yara rules:</h2>

<p align="center">
I transferred the memory file from my host machine to a custom folder on the Kali VM machine to proceed with the next steps.<br/>
  
<img src="https://imgur.com/GGrXmko.png" height="80%" width="80%" alt="DFIR Steps"/>







































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
