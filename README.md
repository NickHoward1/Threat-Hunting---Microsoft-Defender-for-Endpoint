<h1>Threat Hunting</h1>

<h2>Objective</h2>
Gained practical experience in Microsoft Defender for Endpoint (MDE) by performing threat hunting activities, analysing endpoint telemetry and logs, and using investigative tools to detect anomalies and potentially malicious behaviour across four real world attack scenarios.

<h2>Environment</h2>
<ul>
 <li>Microsoft Defender for Endpoint</li>
 
</ul>
<h2>Tasks Completed</h2>
<ul>
 <li>Devices Exposed to the Internet: To identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.</li>
 <li>Sudden Network Slowdowns: </li>
 <li>Suspected Data Exfiltration Employee: </li>
 li>New Zero-Day Announced on News:</li>
</ul>

<h2>Screenshots</h2>

<h2>Devices Exposed to the Internet</h2>

First you want to search for all disticnt device names on the system. 

`DeviceInfo
| distinct DeviceName`

This will bring back a list of devices that are within the organisation, you can then select a device to see if it is internet facing with the query below.

`DeviceInfo
| where DeviceName == "nicks-vm"
| where IsInternetFacing == true
| order by Timestamp desc`

You can then export your findings and save into notes. I would take a screenshot and show the latest instance with the time stamp showing. 

Next you want to see if anyone has tried to login to the VM use the KQL query below. If you don't want to specify one user just remove where DeviceName == "user" this will then bring back a number of remote IP addresses and the number of unsucessful logs that have taken place. 

`DeviceLogonEvents
| Where DeviceName == "nicks-vm"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts`

<img src= "https://github.com/NickHoward1/Threat-Hunting---Microsoft-Defender-for-Endpoint/blob/6ac9222171d88450bfcb260ad2bbb8022e8fee27/Screenshot%202026-05-28%20at%2009.14.14.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

If there were various IP addresses with a high number of attempts, it's important to check to see if they were successful at any point, please use the KQL query below, note: the IP addresses are just example you would swap these. If logs did show this mean an account has been compromised and you would immediately isolate the device in MDE to prevent any later movement or malware from speading across the network. 

`let RemoteIPsInQuestion = dynamic(["119.42.115.235","183.81.169.238", "74.39.190.50", "121.30.214.172", "83.222.191.62", "45.41.204.12", "192.109.240.116"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)`

The KQL query below allows you to see the account names that have succesfully logged in within the business. 

`DeviceLogonEvents
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| distinct AccountName`

Below you can see the KQL query to see if there were any failed login attempts under the Account name nickhoward2, which came back with 0, the second KQl query i replaced fsiled with logonSucess, this came back with 16 sucessful logins, this shows that no threat actors is attempts to login under the username/accountname. If i remove the AccountName from the search you can see that there were 756 failed login attempts showing external IP address attempting a brute force attack. 

DeviceLogonEvents
| where DeviceName == "nicks-vm"
| where LogonType == "Network"
| where ActionType == "LogonFailed" change to "LogonSucess"
| where AccountName == "nickhoward2"

`DeviceLogonEvents
| where DeviceName == "nicks-vm"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| summarize count()`

<img src= "https://github.com/NickHoward1/Threat-Hunting---Microsoft-Defender-for-Endpoint/blob/27c60361e8c1409f2a7258ae24eba9d036169ff1/Screenshot%202026-05-28%20at%2010.10.33.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

This KQL query below is summarising the successful login and the IP addresses connected to it, you can click the IP address and it will give you the geolocaion.

`DeviceLogonEvents
| where DeviceName == "nicks-vm"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "nickhoward2"
| summarize count() by DeviceName, ActionType, AccountName, RemoteIP`


<h2>Sudden Network Slowdowns</h2>

<h2>Suspected Data Exfiltration Employee</h2>

<h2>New Zero-Day Announced on News</h2>
