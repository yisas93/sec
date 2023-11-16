import './App.css';
import { useState } from 'react';




function App() {

const questions=[
  {
    question: "The Chief Technology Officer of a local college would like visitors to utilize the school's WiFi but must  be able to associate potential malicious activity to a specific person.  Which of the following would BEST allow this objective to be met? ",
    answer: "Deploying a captive portal to capture visitors' MAC addresses and names ",
    options: ["Deploying a captive portal to capture visitors' MAC addresses and names ", "Creating a unique PSK for every visitor when they arrive at the reception area", "Implementing a new SSID for every event hosted by the college that has visitors ", "Requiring all new, on-site visitors to configure their devices to use WPS"],
    explanation: "A captive portal is a web page that requires visitors to authenticate or agree to an acceptable use policy before allowing access to the network. By capturing visitors' MAC addresses and names, potential malicious activity can be traced back to a specific person "
  },
  {
    question: "The security team received a report of copyright infringement form the IP space of the corporate network. The report provided a precise time stamp for the incident as well as the name of the copyrighted files. The analyst has been tasked with determining the infringing source machine and instructed to implement measures to prevent such incidents from ocurring again. Which of the following is MOST capable of accomplishing both tasks?",
    answer: "NGFW",
    options: ["HIDS", "Allow list", "TPM", "NGFW"],
    explanation: "Next-Generation Firewalls (NGFW) are designed to provide advanced threat protection by combining traditional firewall capabilitties with intrusion prevention, application control, and other security features. NGFWs can detect and block unauthorized access attempts, malware infections, and other suspicious activity. They can also be used to monitor file access and detect unauthorized copying or distribution of copyrighted material. A next-generation firewall (NGFW) can be used to detect and prevent copyright infringement by analyzing network traffic and blocking unauthorized transfers of copyrighted material. Additionaly, NGFWs can be configured to enforce  access control policies that prevent unauthorized access to sensitive resources."
  },
  {
    question:"A security administrator is setting up a SIEM to help monitor for notable events across the enterprise. Which of the following control types does this BEST represent? ",
    answer:"Detective",
    options:["Detective","Corrective","Compensating","Preventive"],
    explanation:"A SIEM is a security solution that helps detect security incidents by monitoring for notable events across the enterprise. A detective control is a control that is designed to detect security incidents and respond to them. Therefore, a SIEM represents a detective control."
  },
  {
    question:"A systems engineer is building a new system for production. Which of the following is the FINAL step to be performed prior to promoting to production? ",
    answer:" Run a vulnerability scan",
    options:["Encrypt all disks.","Install the latest security patches"," Run a vulnerability scan","Disable unneeded services. "],
    explanation:"Running a vulnerability scan is the final step to be performed prior to promoting a system to production. This allows any remaining security issues to be identified and resolved before the system is put into production."
  },
  {
    question:"A security analyst is reviewing the vulnerability scan report for a web server following an incident. The vulnerability that was used to exploit the server is present in historical vulnerability scan reports, and patch is available for the vulnerability. Which of the following is the MOST likely cause?",
    answer:"Security patches were uninstalled due to user impact",
    options:["Security patches were uninstalled due to user impact","An adversary altered the vulnerability scan reports ","A zero-day vulnerability was used to exploit the web server","The scan reported a false negative for the vulnerability"],
    explanation:"A security patch is a software update that fixes a vulnerability or bug that could be exploited by attackers. Security patches are essential for maintaining the security and functionality of systems and applications. If the vulnerability that was used to exploit the server is present in historical vulnerability scan reports, and a patch is available for the vulnerability, it means that the patch was either not applied or was uninstalled at some point. A possible reason for uninstalling a security patch could be user impact, such as performance degradation, compatibility issues, or functionality loss. "
  },
  {
    question:"A company wants to modify its current backup strategy to modify its current backup strategy to minimize the number of backups that would need to be restored in case of data loss. Which of the following would be the BEST backup strategy ",
    answer:"Full backups followed by incremental backups",
    options:["Full backup followed by different backups ","Full backups followed by incremental backups","Incremental backups followed by delta backups","Delta backups followed by differential backups "],
    explanation:"The best backup strategy for minimizing the number of backups that need to be restored in case of data loss is full backups followed by incremental backups. This strategy allows for a complete restoration of data by restoring the most recent full backup followed by the most recent incremental backup.  "
  },
  {
    question:"A network engineer and a security engineer are discussing ways to monitor network operations. Which of the following is the BEST method? ",
    answer:"Utilize an agentless monitor ",
    options:["Disable Telnet and force SSH. ","Establish a continuous ping.","Utilize an agentless monitor "," Enable SNMPv3 With passwords. "],
    explanation:"An agentless monitor is the best method to monitor network operations because it does not require any software or agents to be installed on the devices being monitored, making it less intrusive and less likely to disrupt network operations. This method can monitor various aspects of network operations, such as traffic, performance, and security. "
  },
  {
    question:"An enterprise needs to keep cryptographic keys in a safe manner. Which of the following network appliances can achieve this goal? ",
    answer:"HSM ",
    options:["HSM ","CASB","TPM","DLP"],
    explanation:"Hardware Security Module (HSM) is a network appliance designed to securely store cryptographic keys and perform cryptographic operations. HSMs provide a secure environment for key management and can be used to keep cryptographic keys safe from theft, loss, or unauthorized access. Therefore, an enterprise can achieve the goal of keeping cryptographic keys in a safe manner by using an HSM appliance. "
  },
  {
    question:"A security administrator wants to implement a program that tests a user's ability to recognize attacks over the organization's email system. Which of the following would be BEST suited for this task? ",
    answer:"Phishing campaign",
    options:["Social media analysis ","Annual information security training","Gamification","Phishing campaign"],
    explanation:"A phishing campaign is a simulated attack that tests a user's ability to recognize attacks over the organization's email system. Phishing campaigns can be used to train users on how to identify and report suspicious emails. "
  },
  {
    question:".As part of annual audit requirements, the security team performed a review of exceptions to the company policy that allows specific users the ability to use USB storage devices on their laptops. The review yielded the following results. • The exception process and policy have been correctly followed by the majority of users • A small number of users did not create tickets for the requests but were granted access • All access had been approved by supervisors. • Valid requests for the access sporadically occurred across multiple departments. • Access, in most cases, had not been removed when it was no longer needed Which of the following should the company do to ensure that appropriate access is not disrupted but unneeded access is removed in a reasonable time frame? ",
    answer:"Create an automated, monthly attestation process that removes access if an employee's supervisor denies the approval",
    options:["Create an automated, monthly attestation process that removes access if an employee's supervisor denies the approval","Remove access for all employees and only allow new access to be granted if the employee's supervisor approves the request","Perform a quarterly audit of all user accounts that have been granted access and verify the exceptions with the management team","Remove access for all employees and only allow new access to be granted if the employee's supervisor approves the request"],
    explanation:"According to the CompTIA Security+ SY0-601 documents, the correct answer option is A. Create an automated, monthly attestation process that removes access if an employee’s supervisor denies the  approval12. This option ensures that appropriate access is not disrupted but unneeded access is removed in a reasonable time frame by requiring supervisors to approve or deny the exceptions on a regular basis. It also reduces the manual workload of the security team and improves the compliance with the company policy"
  },
  {
    question:"Which of the following describes a maintenance metric that measures the average time required to troubleshoot and restore failed equipment? ",
    answer:"MTTR",
    options:["RTO","MTBF","MTTR","RPO"],
    explanation:"Mean Time To Repair (MTTR) is a maintenance metric that measures the average time required to troubleshoot and restore failed equipment. "
  },
  {
    question:"Which of the following isa risk that is specifically associated with hesting applications iin the public cloud?",
    answer:"Shared tenancy",
    options:["Unsecured root accounts","Zero day","Shared tenancy","Insider threat"],
    explanation:"When hosting applications in the public cloud, there is a risk of shared tenancy, meaning that multiple organizations are sharing the same infrastructure. This can potentially allow one tenant to access another tenant's data, creating a security risk."
  },
  {
    question:"The technology department at a large global company is expanding its Wi-Fi network infrastructure at the headquarters building. Which of the following should be closely coordinated between the technology, cybersecurity, and physical security departments? ",
    answer:"WAP placement",
    options:["Authentication protocol","Encryption type","WAP placement","VPN configuration"],
    explanation:"WAP stands for wireless access point, which is a device that allows wireless devices to connect to a wired network using Wi-Fi or Bluetooth. WAP placement refers to where and how WAPs are installed in a building or area. WAP placement should be closely coordinated between the technology, cybersecurity, and physical security departments because it affects several aspects of network performance and security, such as: ✑ Coverage: WAP placement determines how well wireless devices can access the network throughout the building or area. WAPs should be placed in locations that provide optimal signal strength and avoid interference from other sources. ✑ Capacity: WAP placement determines how many wireless devices can connect to the network simultaneously without affecting network speed or quality. WAPs should be placed in locations that balance network load and avoid congestion or bottlenecks. ✑ Security: WAP placement determines how vulnerable wireless devices are to eavesdropping or hacking attacks from outside or inside sources. WAPs should be placed in locations that minimize exposure to unauthorized access and maximize encryption and authentication methods. "
  },
  {
    question:"A company uses a drone for precise perimeter and boundary monitoring. Which of the following should be MOST concerning to the company?",
    answer:"Privacy",
    options:["Privacy","Cloud storage of telemetry data","GPS spoofing","Weather events "],
    explanation:"The use of a drone for perimeter and boundary monitoring can raise privacy concerns, as it may capture video and images of individuals on or near the monitored premises. The company should take measures to ensure that privacy rights are not violated. "
  },
  {
    question:"An organization wants to enable built-in FDE on all laptops. Which of the following should the organization ensure is Installed on all laptops? ",
    answer:"TPM",
    options:["TPM","CA","SAML","CRL"],
    explanation:"The organization should ensure that a Trusted Platform Module (TPM) is installed on all laptops in order to enable built-in Full Disk Encryption (FDE). TPM is a hardware-based security chip that stores encryption keys and helps to protect data from malicious attacks. It is important to ensure that the TPM is properly configured and enabled in order to get the most out of FDE. "
  },
  {
    question:"A security analyst is running a vulnerability scan to check for missing patches during a suspected security rodent During which of the following phases of the response process is this activity MOST likely occurring?",
    answer:"Identification",
    options:["Containment ","Identification","Recovery ","Preparation"],
    explanation:"Vulnerability scanning is a proactive security measure used to identify vulnerabilities in the network and systems. "
  },
  {
    question:"A desktop support technician recently installed a new document-scanning software program on a computer. However, when the end user tried to launch the program, it did not respond. Which of the following is MOST likely the cause?",
    answer:"The software was not added to the application whitelist",
    options:[" A new firewall rule is needed to access the application. ","The system was quarantined for missing software updates.","The software was not added to the application whitelist","The system was isolated from the network due to infected software "],
    explanation:"The most likely cause of the document-scanning software program not responding when launched by the end user is that the software was not added to the application whitelist. An application whitelist is a list of approved software applications that are allowed to run on a system. If the software is not on the whitelist, it may be blocked from running by the system's security policies. Adding the software to the whitelist should resolve the issue and allow the program to run. References: https://www.techopedia.com/definition/31541/application-whitelisting "
  },
  {
    question:"Which of the following is required in order for an IDS and a WAF to be effective on HTTPS traffic? ",
    answer:"TLS inspection",
    options:["Hashing"," DNS sinkhole","TLS inspection","Data masking"],
    explanation:"an IDS (Intrusion Detection System) and a WAF (Web Application Firewall) are both used to monitor and protect web applications from common attacks such as cross-site scripting and SQL injection12. However, these attacks can also be hidden in encrypted HTTPS traffic, which uses the TLS (Transport Layer Security) protocol to provide cryptography and authentication between two communicating applications34. Therefore, in order for an IDS and a WAF to be effective on HTTPS traffic, they need to be able to decrypt and inspect the data that flows in the TLS tunnel. This is achieved by using a feature called TLS inspection345, which creates two dedicated TLS connections: one with the web server and another with the client. The firewall then uses a customer-provided CA (Certificate Authority) certificate to generate an on-the-fly certificate that replaces the web server certificate and shares it with the client. This way, the firewall can see the content of the HTTPS traffic and apply the IDS and WAF rules accordingly"
  },
  {
    question:"Which of the following environments typically hosts the current version configurations and code, compares user-story responses and workflow, and uses a modified version of actual data for testing? ",
    answer:"Staging",
    options:["Development","Staging","Production","Test"],
    explanation:"Staging is an environment in the software development lifecycle that is used to test a modified version of the actual data, current version configurations, and code. This environment compares user-story responses and workflow before the software is released to the production environment. "
  },
  {
    question:"After a WiFi scan of a local office was conducted, an unknown wireless signal was identified Upon investigation, an unknown Raspberry Pi device was found connected to an Ethernet port using a single connection. Which of the following BEST describes the purpose of this device?  ",
    answer:"Rogue access point",
    options:["loT sensor","Evil twin","Rogue access point","On-path attack"],
    explanation:"A Raspberry Pi device connected to an Ethernet port could be configured as a rogue access point, allowing an attacker to intercept and analyze network traffic or perform other malicious activities. "
  },
  {
    question:"During an investigation, the incident response team discovers that multiple administrator accounts were suspected of being compromised. The host audit logs indicate a repeated brute-force attack on a single administrator account followed by suspicious logins from unfamiliar geographic locations. Which of the following data sources would be BEST to use to assess the accounts impacted by this attack?",
    answer:"User behavior analytics",
    options:["User behavior analytics","Dump files","Bandwidth monitors","Protocol analyzer output"],
    explanation:"User behavior analytics (UBA) would be the best data source to assess the accounts impacted by the attack, as it can identify abnormal activity, such as repeated brute-force attacks and logins from unfamiliar geographic locations, and provide insights into the behavior of the impacted accounts."
  },
  {
    question:"A security analyst needs an overview of vulnerabilities for a host on the network. Which of the following is the BEST type of scan for the analyst to run to discover which vulnerable services are running? ",
    answer:"Privileged",
    options:["Non-credentialed ","Web application","Privileged","Internal "],
    explanation:"Privileged scanning, also known as credentialed scanning, is a type of vulnerability scanning that uses a valid user account to log in to the target host and examine vulnerabilities from a trusted user’s perspective. It can provide more accurate and comprehensive results than unprivileged scanning, which does not use any credentials and only scans for externally visible vulnerabilities. "
  },
  {
    question:"An attacker replaces a digitally signed document with another version that goes unnoticed Upon reviewing the document's contents the author notices some additional verbiage that was not originally in the document but cannot validate an integrity issue. Which of the following attacks was used?",
    answer:"Hash substitution",
    options:["Cryptomalware","Hash substitution","Collision","Phishing"],
    explanation:"This type of attack occurs when an attacker replaces a digitally signed document with another version that has a different hash value. The author would be able to notice the additional verbiage, however, since the hash value would have changed, they would not be able to validate an integrity issue."
  },
  {
    question:"The help desk has received calls from users in multiple locations who are unable to access core network services The network team has identified and turned off the network switches using remote commands. Which of the following actions should the network team take NEXT? ",
    answer:"Initiate the organization's incident response plan",
    options:["Disconnect all external network connections from the firewall","Send response teams to the network switch locations to perform updates","Turn on all the network switches by using the centralized management software","Initiate the organization's incident response plan"],
    explanation:"An incident response plan is a set of procedures and guidelines that defines how an organization should respond to a security incident. An incident response plan typically includes the following phases: preparation, identification, containment, eradication, recovery, and lessons learned. If the help desk has received calls from users in multiple locations who are unable to access core network services, it could indicate that a network outage or a denial-of-service attack has occurred. The network team has identified and turned off the network switches using remote commands, which could be a containment measure to isolate the affected devices and prevent further damage. The next action that the network team should take is to initiate the organization’s incident response plan, which would involve notifying the appropriate stakeholders, such as management, security team, legal team, etc., and following the predefined steps to investigate, analyze, document, and resolve the incident."
  },
  {
    question:".When planning to build a virtual environment, an administrator need to achieve the following, • Establish polices in Limit who can create new VMs • Allocate resources according to actual utilization‘ • Require justication for requests outside of the standard requirements. • Create standardized categories based on size and resource requirements Which of the following is the administrator MOST likely trying to do? ",
    answer:"Avoid VM sprawl ",
    options:["Implement IaaS replication","Product against VM escape","Deploy a PaaS ","Avoid VM sprawl "],
    explanation:"The administrator is most likely trying to avoid VM sprawl, which occurs when too many VMs are created and managed poorly, leading to resource waste and increased security risks. The listed actions can help establish policies, resource allocation, and categorization to prevent unnecessary VM creation and ensure proper management."
  },
  {
    question:"A company Is planning to install a guest wireless network so visitors will be able to access the Internet. The stakeholders want the network to be easy to connect to so time is not wasted during meetings. The WAPs are configured so that power levels and antennas cover only the conference rooms where visitors will attend meetings.  Which of the following would BEST protect the company's Internal wireless network against visitors accessing company resources? ",
    answer:"Configure the guest wireless network to be on a separate VLAN from the company's internal wireless network",
    options:["Configure the guest wireless network to be on a separate VLAN from the company's internal wireless network","Change the password for the guest wireless network every month.","Decrease the power levels of the access points for the guest wireless network. ","Enable WPA2 using 802.1X for logging on to the guest wireless network. "],
    explanation:"Configuring the guest wireless network on a separate VLAN from the company's internal wireless network will prevent visitors from accessing company resources. "
  },
  {
    question:"An analyst is working on an email security incident in which the target opened an attachment containing a worm. The analyst wants to implement mitigation techniques to prevent further spread. Which of the following is the BEST course of action for the analyst to take? ",
    answer:"Implement network segmentation ",
    options:["Apply a DLP solution.","Implement network segmentation ","Utilize email content filtering, ","isolate the infected attachment. "],
    explanation:"Network segmentation is the BEST course of action for the analyst to take to prevent further spread of the worm. Network segmentation helps to divide a network into smaller segments, isolating the infected attachment from the rest of the network. This helps to prevent the worm from spreading to other devices within the network. Implementing email content filtering or DLP solution might help in preventing the email from reaching the target or identifying the worm, respectively, but will not stop the spread of the worm. "
  },
  {
    question:"A security engineer needs to create a network segment that can be used for servers thal require connections from untrusted networks. Which of the following should the engineer implement? ",
    answer:" A screened subnet",
    options:["An air gap ","A hot site ","A VUAN"," A screened subnet"],
    explanation:"A screened subnet is a network segment that can be used for servers that require connections from untrusted networks. It is placed between two firewalls, with one firewall facing the untrusted network and the other facing the trusted network. This setup provides an additional layer of security by screening the traffic that flows between the two networks. "
  },
  {
    question:"A company was compromised, and a security analyst discovered the attacker was able to get access to a service account. The following logs were discovered during the investigation: Which of the following MOST likely would have prevented the attacker from learning the service account name? ",
    answer:"Input sanitization",
    options:["Race condition testing ","Proper error handling ","Forward web server logs to a SIEM ","Input sanitization"],
    explanation:"Input sanitization can help prevent attackers from learning the service account name by removing potentially harmful characters from user input, reducing the likelihood of successful injection attacks."
  },
    {
    question:"You've hired a third-party to gather information about your company's servers and data. The third-party will not have direct access to your internal network but can gather information from any other source. Which of the following would BEST describe this approach?",
    answer:"Passive footprinting",
    options:["Backdoor testing","Passive footprinting","OS fingerprinting","Partially known environment"],
    explanation:"Passive footprinting focuses on learning as much information from open sources such as social media, corporate websites, and business organizations."
  },
  {
    question:"Which of these threat actors would be MOST likely to attack systems for direct financial gain?",
    answer:"Organized crime",
    options:["Organized crime","Hacktivist","Nation State","Competitor"],
    explanation:"An organized crime actor is motivated by money, and their hacking objectives are usually based around objectives that can be easily exchanged for financial capital"
  },
  {
    question:"An IPS at your company has found a sharp increase in traffic from all-in-one printers. After researching, your security team has found a vulnerability associated with these devices that allows the device to be remotely controlled by a third-party. Which category would BEST describe these devices",
    answer:"MFD",
    options:["IoT","RTOS","MFD","SoC"],
    explanation:"An all-in-one printer that can print, scan, and fax is often categorized as an MFD (Multifunction Device)."
  },
  {
    question:"Which of the following standards provides information on privacy and managing PII",
    answer:"ISO 27701",
    options:["ISO 31000","ISO 27002","ISO 27701","ISO 27001"],
    explanation:"The ISO (International Organization for Standardization) 27701 standard extends the ISO 27001 and 27002 standards to include detailed management of PII (Personally Identifiable Information) and data privacy"
  },
  {
    question:"Elizabeth, a security administrator, is concerned about the potential for data exfiltration using external storage drives. Which of the following would be the BEST way to prevent this method of data exfiltration?",
    answer:"Create an operating system security policy to prevent the use of removable media",
    options:["Create an operating system security policy to prevent the use of removable media","Monitor removable media usage in host-based firewall logs","Only allow applications that do not use removable media","Define a removable media block rule in the UTM"],
    explanation:"Removable media uses hot-pluggable interfaces such as USB to connect storage drives. A security policy in the operating system can prevent any files from being written to a removable drive"
  },
  {
    question:"A CISO would like to decrease the response time when addressing security incidents. Unfortunately, the company does not have the budget to hire additional security engineers. Which of the following would assist the CISO with this requirement?",
    answer:"SOAR",
    options:["ISO 27001","PKI","IaaS","SOAR"],
    explanation:"SOAR (Security Orchestration, Automation, and Response) is designed to make security teams more effective by automating processes and integrating third-party security tools."
  },
  {
    question:" Rodney, a security engineer, is viewing this record from the firewall logs:UTC 04/05/2018 03:09:15809 AV Gateway Alert 136.127.92.171 80 -> 10.16.10.14 60818 Gateway Anti-Virus Alert:XPACK.A_7854 (Trojan) blocked.Which of the following can be observed from this log information?",
    answer:"A download was blocked from a web server",
    options:["The victim's IP address is 136.127.92.171","A download was blocked from a web server","A botnet DDoS attack was blocked","The trojan was locked but the file was not"],
    explanation:"A traffic flow from a web server port number (80) to a device port (60818) indicates that this traffic flow originated on port 80 of the web server. A file download is one of the most common ways to deliver a Trojan, and this log entry shows that the file containing the XPACK.A_7854 Trojan was blocked."
  },
  {
    question:" A user connects to a third-party website and receives this message:Your connection is not private. NET::ERR_CERT_INVALIDWhich of the following attacks would be the MOST likely reason for this message?",
    answer:"On-path",
    options:["Brute-force","DoS","On-path","Dissasociation"],
    explanation:"An on-path attack is often associated with a third-party who is actively intercepting network traffic. This entity in the middle would not be able to provide a valid SSL certificate for a third-party website, and this error would appear in the browser as a warning"
  },
  {
    question:"Which of the following would be the BEST way to provide a website login using existing credentials from a third-party site?",
    answer:"Federation",
    options:["Federation","802.1x","PEAP","EAP-FAST"],
    explanation:"Federation would allow members of one organization to authenticate using the credentials of another organization"
  },
  {
    question:"A system administrator, Daniel, is working on a contract that will specify a minimum required uptime for a set of Internet-facing firewalls. Daniel needs to know how often the firewall hardware is expected to fail between repairs. Which of the following would BEST describe this information?",
    answer:"MTBF",
    options:["MTBF","RTO","MTTR","MTTF"],
    explanation:"he MTBF (Mean Time Between Failures) is a prediction of how often a repairable system will fail."
  },
  {
    question:"An attacker calls into a company's help desk and pretends to be the director of the company's manufacturing department. The attacker states that they have forgotten their password and they need to have the password reset quickly for an important meeting. What kind of attack would BEST describe this phone call?",
    answer:"Social engineering",
    options:["Social engineering","Tailgating","Vishing","On-path"],
    explanation:"A social engineering attack takes advantage of authority and urgency principles in an effort to convince someone else to circumvent normal security controls."
  },
  {
    question:"A security administrator has been using EAP-FAST wireless authentication since the migration from WEP to WPA2. The company's network team now needs to support additional authentication protocols inside of an encrypted tunnel. Which of the following would meeet the network team's requirements",
    answer:"EAP-TTLS",
    options:["EAP-TLS","PEAP","EAP-TTLS","EAP-MSCHAPv2"],
    explanation:"EAP-TTLS (Extensible Authentication Protocol - Tunneled Transport Layer Security) allows the use of multiple authentication protocols transported inside of an encrypted TLS (Transport Layer Security) tunnel. This allows the use of any authentication while maintaining confidentiality with TLS."
  },
  {
    question:"The embedded OS in a company's time clock appliance is configured to reset the file system and reboot when a file system error occurs. On one of the time clocks, this file system error occurs during the startup process and causes the system to constantly reboot. Which of the following Best describes this issue?",
    answer:"Race condition",
    options:["DLL injection","Resource exhaustion","Race condition","Weak configuration"],
    explanation:"A race condition occurs when two processes occur at similar times, usually with unexpected results. The file system problem is usually fixed before a reboot, but a reboot is occurring before the fix can be applied. This has created a race condition that results in constant reboots"
  },
  {
    question:"A security team has been provided with a non-credentialed vulnerability scan report created by a third-party. Which of the following would they expect to see on this report?",
    answer:"The version of web server software in use",
    options:["A summary of all files with invalid group assignments","A list of all unpatched operating system files","The version of web server software in use","A list of local user accounts"],
    explanation:"A scanner like Nmap can query services and determine version numbers without any special rights or permissions, which makes it well suited for non-credentialed scans"
  },
  {
    question:"A business manager is documentating a set of steps for processing orders if the primary Internet connection fails. Which of these would best describe these steps?",
    answer:"Continuity of operations",
    options:["Communication plan","Continuity of operations","Stakeholder management","Tabletop exercise"],
    explanation:"It's always useful to have an alternative set of processes to handle any type of outage or issue. Continuity of operations planning ensures that the business will continue to operate when these issues occur."
  },
  {
    question:"A security administrator is concerned about data exfiltration resulting from the use of malicious phone charging stations. Which of the following would be the best way to protect against this threat?",
    answer:"USB data blocker",
    options:["USB data blocker","Personal firewall","MFA","FDE"],
    explanation:"USB data blockers are physical USB cables that allow power connections but prevent data connections. With a USB data blocker attached, any power source can be used without a security concern"
  },
  {
    question:"A company would like to protect the data stored on laptops used in the field. Which of the following would be the best choice for this requirement",
    answer:"SED",
    options:["MAC","SED","CASB","SOAR"],
    explanation:"A SED (Self-Encrypting Drive) provides data protection of a storage device using full-disk encryption in the drive hardware"
  },
  {
    question:"A file server has full backup performed each monday at 1 am. Incremental backups are performed at 1 am on tuesday, wednesday, thursday and friday. The system administrator needs to perform a full recovery of the file server on thursday afternoon. How many backup sets would be required to complete the recovery?",
    answer:"4",
    options:["2","3","4","1"],
    explanation:"Each incremental backup will archive all of the files that have changed since the last full or incremental backup. To complete this full restore, the administrator will need the full backup from Monday and the incremental backups from Tuesday, Wednesday, and Thursday"
  },
  {
    question:"A security engineer runs a monthly vulnerability scan. The scan doesn't list any vulnerabilities for Windows servers, but a significant vulnerability was announced last week and none of the servers are patched yet. Which of the following best describes this result?",
    answer:"False negative",
    options:["Exploit","Credentialed","Zero-day attack","False negative"],
    explanation:"A false negative is a result that fails to detect an issue when one actually exists"
  },
  {
    question:"A network administrator would like each user to authenticate with their personal username and password when connecting to the company's wireless network. Which of the following should the network administrator configure on the wireless access points?",
    answer:"802.1x",
    options:["WPA2-PSK","802.1x","WPS","WPA2-AES"],
    explanation:"802.1X uses a centralized authentication server, and all users can use their normal credentials to authenticate to an 802.1X network."
  },
  {
    question:"A user has assigned individual rights and permissions to a file on their network drive. The user adds three additional individuals to have read-only access to the file. Which of the following would describe this access control mode?",
    answer:"DAC",
    options:["DAC","MAC","ABAC","RBAC"],
    explanation:"DAC (Discretionary Access Control) is used in many operating systems, and this model allows the owner of the resource to control who has access"
  },
  {
    question:"A remote user has received a text message requesting login details to the corporate VPN server. Which of the following would BEST describe this message?",
    answer:"Smishing",
    options:["Brute force","Prepending","Typosquatting","Smishing"],
    explanation:"Smishing, or SMS phishing, is a social engineering attack that asks for personal information using SMS or text messages"
  },
  {
    question:"A company hires a large number of seasonal employees, and their system access should normally be disabled when the employee leaves the company. The security administrator would like to verify that their systems cannot be accessed by any of the former employees. Which of the following would be the best way to provide this verification?",
    answer:"",
    options:["Confirm that no unauthorized accounts have administrator access","Validate the account lockout policy","Validate the process and procedures for all outgoing employees","Create a report that shows all authentications for a 24-hour period"],
    explanation:"The disabling of an employee account is commonly part of the offboarding process. One way to validate an offboarding policy is to perform an audit of all accounts and compare active accounts with active employees"
  },
  {
    question:"A manufacturing company has moved an inventory application from their internal systems to a PaaS service. Which of the following would be the best way to manage security policies on this new service?",
    answer:"CASB",
    options:["DLP","SIEM","IPS","CASB"],
    explanation:"A CASB (Cloud Access Security Broker) is used to manage compliance with security policies when using cloud-based applications."
  },
  {
    question:"An organization has identified a significant vulnerability in a firewall used for Internet connecivity. The firewall company has stated there are no plans to create a patch for this vulnerability. Which of the following would best describe this issue?",
    answer:"Lack of vendor support",
    options:["Lack of vendor support","Improper input handling","Improper key management","End-of-life"],
    explanation:"Security issues can be identified in a system or application at any time, so it’s important to have a vendor that can support their software and correct issues as they are discovered. If a vendor won’t provide security patches, then you may be susceptible to security vulnerabilities"
  },
  {
    question:"A security administrator needs to identify all computers on the company network infected with a specific malware variant. Which of the following would be the BEST way to identify these systems?",
    answer:"DNS sinkhole",
    options:["Honeynet","Data masking","DNS sinkhole","DLP"],
    explanation:"A DNS (Domain Name System) sinkhole can be used to redirect and identify devices that may attempt to communicate with an external command and control (C2) server. The DNS sinkhole will resolve an internal IP address and can report on all devices that attempt to access the malicious domain."
  },
  {
    question:"A system administrator has been called to a system that is suspended to have a malware infection. The administrator has removed the device from the network and has disconnected all USB flash drives. Which of these incident response steps is the administrator following?",
    answer:"Containment",
    options:["Lessons learned","Containment","Detection","Reconstitution"],
    explanation:"The containment phase isolates the system from any other devices to prevent the spread of any malicious software."
  },
  {
    question:"Which part of the PC startup process verifies the digital signature of the OS kernel?",
    answer:"Trusted boot",
    options:["Measured boot","Trusted boot","Secure boot","POST"],
    explanation:"he Trusted Boot portion of the startup process verifies the operating system kernel signature and starts the ELAM (Early Launch Anti-Malware) process."
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },
  {
    question:"",
    answer:"",
    options:["","","",""],
    explanation:""
  },

]
const [currentQuestion, setCurrentQuestion]=useState(0)


const handleNextQuestion=()=>{
  setCurrentQuestion(currentQuestion +1)
  setColor("white")
  setColor2("white")
  setColor3("white")
  setColor4("white")
  setExplanation(false)

}
const handlePrevQuestion=()=>{
  if (currentQuestion>0){
    setCurrentQuestion(currentQuestion -1)
    setColor("white")
    setColor2("white")
    setColor3("white")
    setColor4("white")
    setExplanation(false)
    
  }
}




const value1 = questions[currentQuestion].options[0]
const value2 = questions[currentQuestion].options[1]
const value3 = questions[currentQuestion].options[2]
const value4 = questions[currentQuestion].options[3]
const [color, setColor]=useState("white")
const [color2, setColor2]= useState("white")
const [color3, setColor3]= useState("white")
const [color4, setColor4]= useState("white")
const handleAnswer=()=>{
  if (value1 === questions[currentQuestion].answer){
    setColor(" rgb(0, 255, 0)")
  }else{
    setColor("red")
  }
  if (value2 === questions[currentQuestion].answer){
    setColor2(" rgb(0, 255, 0)")
  }else{
    setColor2("red")
  }
  if (value3 === questions[currentQuestion].answer){
    setColor3(" rgb(0, 255, 0)")
  }else{
    setColor3("red")
  }
  if (value4 === questions[currentQuestion].answer){
    setColor4(" rgb(0, 255, 0)")
  }else{
    setColor4("red")
  }
}


const [explanation, setExplanation]= useState(false)
const handleExplanation=()=>{
  if (explanation ==true){
    setExplanation(false)
  }else{
    setExplanation(true)
  }
}

return (
  <div className="App">
  <div className="row mt-3 mt-sm-5">
      <div className="col-11 col-sm-8 mx-auto" >
        <div className="question" >
           <p>{questions[currentQuestion].question}</p>
        </div>
        <div className="d-grid">

    
          <div className="d-grid d-md-flex justify-content-center row" >
            <div className="button col-6">
              <div className='action' onClick={handleAnswer}  style={{background: color}} >
                {value1}
              </div>
            </div>
            <div className="button col-6">
              <div className='action' onClick={handleAnswer}  style={{background: color2}}>
              {value2}
            </div>
            </div>
          </div>

          <div className="d-grid d-md-flex row">
            <div className="button col-6">
              <div className='action' onClick={handleAnswer} style={{background: color3}}>
                {value3}
              </div>
            </div>
            <div className="button col-6">
              <div className='action' onClick={handleAnswer} style={{background: color4}}>
                {value4}
              </div>
            </div>
          </div>

      </div>
     
     <div className='d-flex row'>
      <div className=" col-4 "  >
        <button className='page' onClick={handlePrevQuestion}>
        prev</button>

        
      </div>
      <div className=" col-4 ms-auto" >
            <button className='page' onClick={handleNextQuestion}>next</button>
      </div>
  
     </div>
      

      </div>
      <div className="row">
        <div className="col-5 mx-auto">
         <button className='btn-exp' onClick={handleExplanation}>explanation</button> 
        </div>
      </div>
      
      {explanation===true?
      <div className="container-fluid">
        <div className="col-11 d-flex justify-content-center col-sm-8 mx-auto">
           <button className="explanation">
      {questions[currentQuestion].explanation}
       </button>
        </div>
   
   </div>:""
      
      }
   

   
  </div>
  
</div>
  );
}

export default App;
