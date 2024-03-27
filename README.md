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
Once the Suricata service is installed in our VM, some configurations must be made for it to work. The configuration file path can be found in the screenshot. First, I changed the #HOME_NET IP address range to listen to my real home IP range which is 192.168.200.0/24  <br/>
  
<img src="https://imgur.com/uO7oTYY.png" height="80%" width="80%" alt="Suricata Steps"/>
<br />
<br />
Secondly, I enabled the community-id to be “true”:  <br/>
  
<img src="https://imgur.com/L9DNmSg.png" height="80%" width="80%" alt="Suricata Steps"/>
<br />
<br />
Made sure the af-packet is linked with our network interface. Mine is eth0.: <br/>
  
<img src="https://imgur.com/qvywVM6.png" height="80%" width="80%" alt="Suricata Steps"/>
<br />
<br />
Last, I changed to default-rule-path to /var/lib/suricata/rules as the final configuration:  <br/>
  
<img src="https://imgur.com/jMFGrGA.png" height="80%" width="80%" alt="Suricata Steps"/>
<br />
<br />
</p>

<h2>Lab 1 TCP SYN Floods walk-through:</h2>

<p align="left">
Testing situation for TCP SYN Floods: <br/>
  
<img src="https://imgur.com/SnlC5Na.png" height="80%" width="80%" alt="Suricata Steps"/><br />
 
  Explanation:
- Alert: action that we set if the data matches the rule description
- Tcp: monitoring TCP packets 
- $EXTERNAL_NET any -> $HOME_NET any: monitoring traffic from external IP address range from any port to home IP address range (i.e. 192.168.200.0/24) and any port. Vice versa. 
- Msg: log message when it pops up in Suricata log or JSON files
- Flow: to_server:  set to monitor and detect the communication to the server as well 
- Flag: Means TCP flag. Here we set it to monitor the “SYN” flag in the 3-way handshake protocol level. 
- Threshold: set it with conditions before it generates an alert with packeting counts and seconds, track it either destination IP or source IP, etc. Usually, the conditions are made according to the characteristics of the attack
- Classtype: classification of the rules and alerts. 
- Sid: custom number for each rule identification
- Rev: rule version


#Testing Steps:


Used two different VMs for this testing scenario with different IP addresses 

<img src="https://imgur.com/ZVvYxN5.png" height="80%" width="80%" alt="Suricata Steps"/><br />

- On the testing VM, first we installed with ethtool package by typing: sudo apt-get install ethtool -y 
- Then we typed another command to disable packet offload: sudo ethtool -K eth0 gro off lro off 
- Last, we enabled Suricata and ran it in system mode by typing the following: sudo suricata -c /etc/suricata/suricata.yaml -q 0 &

<img src="https://imgur.com/bIAUXmZ.png" height="80%" width="80%" alt="Suricata Steps"/><br />

On the remote machine, we typed the following command to send non-stop packets to our main machine for Suricata detection:
- Sudo hping3 -S -p 80 --flood --rand-source 192.168.200.128

<img src="https://imgur.com/s6FUdb7.png" height="80%" width="80%" alt="Suricata Steps"/><br />


#Results from fast.log:


<img src="https://imgur.com/NpQU5JE.png" height="80%" width="80%" alt="Suricata Steps"/><br />
<br />
<br />
</p>

<h2>Lab 2 SQL Injection attack walk-through:</h2>

<p align="left">
Testing situation for SQL Injection attack:  <br/>
  
<img src="https://imgur.com/NJLRSYw.png" height="80%" width="80%" alt="Suricata Steps"/><br />

  Explanation:
- Alert: action that we set if the data matches the rule description
- Tcp: monitoring HTTP packets 
- Any any-> Any any: monitoring traffic from any IP address range from any port to any IP address range on the network and any port. 
- Msg: log message when it pops up in Suricata log or JSON files
- Flow: established,to_server:  set to monitor and detect the communication to the server as well but limit it to search for packets of established connections only matching the signatures. 
- Nocase: case insensitive search enabling function.  
- HTTP_: request keywords 
- Sid: custom number for each rule identification


#Testing Steps:

Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application that is to aid penetration testers and security professionals to test their skills and tools. To perform the testing, I needed to install DVWA in my testing Kali Linux machine but I will not go through the installation steps in this lab. Once I did, I typed 127.0.01 (my localhost IP address) in the browser for this main page.  

<img src="https://imgur.com/9JGcpgW.png" height="80%" width="80%" alt="Suricata Steps"/><br />

Set it to a low level so I could let the Suricata detect more easily.

<img src="https://imgur.com/O5ceT9u.png" height="80%" width="80%" alt="Suricata Steps"/><br />

Clicked the SQL Injection from the left side, then clicked submit

<img src="https://imgur.com/YgbCBMn.png" height="80%" width="80%" alt="Suricata Steps"/><br />

#Results from fast.log:


<img src="https://imgur.com/caQRxnV.png" height="80%" width="80%" alt="Suricata Steps"/><br />

<br />
<br />
</p>

<h2>Lab 3 Phishing walk-through:</h2>

<p align="left">
Testing situation for Phishing attack:  <br/>
  
<img src="https://imgur.com/v52PAJ1.png" height="80%" width="80%" alt="Suricata Steps"/><br />

  Explanation:
-  Alert: action that we set if the data matches the rule description
-  DNS: monitoring all DNS packets 
-  Any any-> Any 53: monitoring traffic from any IP address range from any port to any IP address range on the network but particularly via Port 53 which is TCP/UDP for DNS service. 
-  Msg: log message when it pops up in Suricata log or JSON files
-  DNS_query: keyword that indicates all DNS request queries will be inspected
-  Content: payloads/keywords that we would like our search to match specifically 
-  Nocase: case insensitive search enabling function.  
-  Isdataat: look if there is still data at a specific part of the payload, we set 1 byte here.
-  Sid: custom number for each rule identification
-  Rev: rule version


#Testing steps and the result from fast.log: 

I pinged the domain and there was a DNS query service running in behind, so it hit the rule and appeared in the log file. 

<img src="https://imgur.com/NiLJCGy.png" height="80%" width="80%" alt="Suricata Steps"/><br />

<br />
<br />
</p>

<h2>Lab 4 Unauthorized protocol and traffic walk-through:</h2>

<p align="left">
Testing situation for this attack:  <br/>
  
<img src="https://imgur.com/dm9HnW1.png" height="80%" width="80%" alt="Suricata Steps"/><br />

  Explanation:
- Alert: action that we set if the data matches the rule description
- TCP: monitoring all TCP packets 
- Any any-> Any ![80,8080] or 80: monitoring traffic from any IP address range from any port to any IP address range on the network, particularly outside of Port 80&8080 for HTTP service. The! here means -excluding. The 2nd rule is monitoring Port 80 though. 
- Msg: log message when it pops up in Suricata log or JSON files
- Flow: to_server:  set to monitor and detect the communication to the server as well 
- App-layer-protocol: specifying which protocol we wanted to monitor and search  
- Sid: custom number for each rule identification
- Rev: rule version


#Testing steps: 

To start off, there are two configurations I had to make.Ports.conf and 000-default.conf. I went to the directory where they belonged. 

<img src="https://imgur.com/B78y4V3.png" height="80%" width="80%" alt="Suricata Steps"/><br />


Type: sudo nano 000-default.conf. 

In <VirtualHost *:>, I typed 4848 which is a UDP port for datagram service, here to make my Apache server listen to this port. 

Then save and exit. 

<img src="https://imgur.com/71FhKeF.png" height="80%" width="80%" alt="Suricata Steps"/><br />


After that, I went to the directory /etc/apache2 and I typed:
- Sudo nano ports.conf

The Apache port is configured to listen to Port 4848 which is 4800. Save and exit. All configurations are made.

<img src="https://imgur.com/71FhKeF.png" height="80%" width="80%" alt="Suricata Steps"/><br />

Then I typed the following commands to restart my Apache server and check its status: 
- Sudo systemctl restart apache2.service
- Sudo systemctl status apache2.service

<img src="https://imgur.com/rI1YVOC.png" height="80%" width="80%" alt="Suricata Steps"/><br />

In this testing, I used 2 different VMs here with different IPs as well. I will not go through the installation part of the Apache server here in this assignment. Once it was successfully installed, we can open it in another VM by typing another VM IP address in the browser and it would show the Apache2 Debian Default Page.

<img src="https://imgur.com/26XEw08.png" height="80%" width="80%" alt="Suricata Steps"/><br />

Since I made the configuration, I typed the IP address via port 4848 again and it was fine that I could go to this main page again.

<img src="https://imgur.com/Ki0rzy8.png" height="80%" width="80%" alt="Suricata Steps"/><br />


#Result from fast.log: 

Since we are using Port 484, it hits the rule description of noting using Port 80 or 8080. We got our results.

<img src="https://imgur.com/6VdecM7.png" height="80%" width="80%" alt="Suricata Steps"/><br />

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
