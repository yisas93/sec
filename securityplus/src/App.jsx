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
  if (value1 == questions[currentQuestion].answer){
    setColor(" rgb(0, 255, 0)")
  }else{
    setColor("red")
  }
  if (value2 == questions[currentQuestion].answer){
    setColor2(" rgb(0, 255, 0)")
  }else{
    setColor2("red")
  }
  if (value3 == questions[currentQuestion].answer){
    setColor3(" rgb(0, 255, 0)")
  }else{
    setColor3("red")
  }
  if (value4 == questions[currentQuestion].answer){
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

        
          <div className="d-flex row" >
            <div className="button col-6">
               <button className='action' onClick={handleAnswer}  style={{background: color}} >
          {value1}
         </button>
            </div>
            <div className="button col-6">
               <button className='action' onClick={handleAnswer}  style={{background: color2}}>
          {value2}
         </button>
              </div>
        
         </div>

         <div className="d-flex row">
          <div className="button col-6">
              <button className='action' onClick={handleAnswer} style={{background: color3}}>
          {value3}
         </button>
          </div>
         <div className="button col-6">
          <button className='action' onClick={handleAnswer} style={{background: color4}}>
          {value4}
         </button>

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
          
          {explanation==true?
          <div className="row">
            <div className="col-12 col-sm-8 mx-auto">
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
