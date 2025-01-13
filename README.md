
# PROJECT NAME

Memory Dump Analysis 

## Objective

Scenario: On May 2, 2024, a multinational corporation identified suspicious PowerShell processes on critical systems, indicating a potential malware infiltration. This activity poses a threat to sensitive data and operational integrity.

You have been provided with a memory dump (memory.dmp) from the affected system. Your task is to analyze the dump to trace the malware's actions, uncover its evasion techniques, and understand its persistence mechanisms.

### Tactics

-Execution
-Persistence

### Tools Used

-Volatility 3

## Steps

Question: Identifying the parent process reveals the source and potential additional malicious activity. What is the name of the suspicious process that spawned two malicious PowerShell processes? 

First thing I need to do is open up the terminal and run the following command. This lists all the active processes. 

![image](https://github.com/user-attachments/assets/214a4324-69db-4c63-b8ce-e8b13e185ea9)

From the output I notice that there are two processes with the same parent process ID (PPID) 4596

![image](https://github.com/user-attachments/assets/655e9f80-9ae6-4ea9-a836-6f2ee787fc88)

Next I run psscan and grep to gather more info on PPID 4596. I use psscan as its not limited to active processes

![image](https://github.com/user-attachments/assets/b6e6b628-0623-4ad9-881b-000a1f40128d)

From the output I notice the process InvoicecheckLi which is partially cut off. I will use cmdline to see the full process name

![image](https://github.com/user-attachments/assets/84f8f838-891b-4c59-8918-4230e9028a8b)

The output shows the process name. InvoiceCheckList.exe

Question: By determining which executable is utilized by the malware to ensure its persistence, we can strategise for the eradication phase. Which executable is responsible for the malware's persistence? 

Since malware is designed to run even after restarts and users logging off, they are designed to relaunch using scheduled tasks or running them as a windows service. From the previous psscan I can see PPID 4596 is also associated with process schtasks.exe 

![image](https://github.com/user-attachments/assets/386d7d94-68d7-4dbf-a64f-ffa2114207aa)

Question: Understanding child processes reveals potential malicious behavior in incidents. Aside from the PowerShell processes, what other active suspicious process, originating from the same parent process, is identified? 

That would be RegSvcs.exe as seen from previous psscan 

Question: Analyzing malicious process parameters uncovers intentions like defense evasion for hidden, stealthy malware. What PowerShell cmdlet used by the malware for defense evasion?

From a previous task, there was a command “Add-MpPreference” that was used to exclude a file from Windows Defender scan. I will run it again so we can see. 


Here we can see Add-MpPreference is used to exclude InvoiceCheckList.exe and HcdmIYYf.exe from Windows Defender Scans.

![image](https://github.com/user-attachments/assets/fc06ccae-ecd9-4ff9-a2cc-3cac9047a958)

Question: Recognizing detection-evasive executables is crucial for monitoring their harmful and malicious system activities. Which two applications were excluded by the malware from the previously altered application's settings? 

We got the answer in the previous task.  InvoiceCheckList.exe and HcdmIYYf.exe

Question: What is the specific MITRE sub-technique ID associated with PowerShell commands that aim to disable or modify antivirus settings to evade detection during incident analysis?

I go to https://attack.mitre.org/ disabling or modifying antivirus would call under Defense Evasion> Impair Defenses.  Sub-Technique would be Disable or Modify Tools T1562.001

![image](https://github.com/user-attachments/assets/4708ba54-ad31-4665-9e1c-3efd4d890908)

Question: Determining the user account offers valuable information about its privileges, whether it is domain-based or local, and its potential involvement in malicious activities. Which user account is linked to the malicious processes?

For this I will need to use getsids. SID (Security ID) is assigned to each account.  The output below shows user Lee has been running malicious processes

![image](https://github.com/user-attachments/assets/4f9ae68b-8318-430b-a2be-98ce4f59898c)

End of Lab
