# Incident Report: OTRF APT29 Evals Day 1 — Multi-Host Windows Intrusion

## Executive Summary

This investigation reviewed OTRF APT29 Evals Day 1 host telemetry and the associated SCRANTON/NASHUA network captures. The dataset represents a controlled adversary-emulation exercise; the findings below describe observed behavior in that dataset and do not establish a real-world compromise or attribute the activity to the APT29 threat group.

The strongest supported activity chain begins on **SCRANTON** (`10[.]0[.]1[.]4`), where a suspicious `.scr` executable ran from `C:\ProgramData\victim\...`. Subsequent PowerShell activity interacted with `monkey.png`, created a password-protected `OfficeSupplies.7z` archive from the Downloads directory, and copied that archive to a WebDAV endpoint at `192[.]168[.]0[.]4:80`. The packet capture contains a `PUT` for `/webdav/OfficeSupplies.7z` with a content length of 1,082,089 bytes and a server response of `204 No Content`, supporting a successful upload to that WebDAV service.

The same exercise contains a strong lateral-movement sequence from SCRANTON to **NASHUA** (`10[.]0[.]1[.]6`). SMB traffic shows access to `ADMIN$`, transfer of `Temp\python.exe`, and PsExec-related service control (`PSEXESVC.exe`, `svcctl`, `OpenSCManager2`, and `CreateServiceW`). NASHUA host telemetry then records `python.exe` and a child PowerShell process. PowerShell searched the user profile for files matching document, archive, image, shortcut, and credential-related patterns, then created `%APPDATA%\working.zip`. `Rar.exe` created a password-protected archive on the Desktop. SDelete subsequently shredded the Desktop archive and selected tooling.

NASHUA Sysmon Event ID 3 telemetry also records 348 network events attributed to `C:\Windows\Temp\python.exe` (PID 2172) communicating with `192[.]168[.]0[.]4:8443`. The purpose and contents of that traffic were not established. Separately, SCRANTON communicated periodically over TLS with `192[.]168[.]0[.]5:443`; this is suspicious but remains an unconfirmed C2 hypothesis.

**Assessment:** High confidence in the observed SCRANTON-to-NASHUA SMB/PsExec transfer-and-execution sequence and in the SCRANTON WebDAV upload. High confidence that NASHUA performed PowerShell-based file discovery and archive creation. The destination ownership and externality of the WebDAV service, the purpose of the TLS sessions, persistence via `hostui.lnk`, and any NASHUA exfiltration remain unconfirmed.

**No evidence in the reviewed subset establishes ransomware behavior, BitLocker volume encryption, or APT29 attribution.**

## Affected / Relevant Systems

|System / endpoint|Role in the reviewed data|Assessment|
|---|---|---|
|`10[.]0[.]1[.]4` — `SCRANTON.dmevals[.]local`|Initial suspicious `.scr` execution, PowerShell activity, archive creation, WebDAV upload, and SMB/PsExec source|Primary investigated host|
|`10[.]0[.]1[.]6` — `NASHUA.dmevals[.]local`|Receives `python.exe` over SMB; PsExec service execution; Python/PowerShell collection and archive activity|Secondary investigated host|
|`10[.]0[.]0[.]4` — `NEWYORK.dmevals[.]local`|Observed in SMB/IPC$, SYSVOL, LDAP/Kerberos-related activity|Domain infrastructure context; not identified as the attacker|
|`192[.]168[.]0[.]4:80`|Apache WebDAV service under `/webdav/`; receives `OfficeSupplies.7z` and serves `python.exe` metadata/content|Lab endpoint; server ownership/externality not established|
|`192[.]168[.]0[.]4:8443`|Destination of NASHUA `python.exe` network events|TLS endpoint; application purpose unknown|
|`192[.]168[.]0[.]5:443`|Destination of a long SCRANTON TLS communication|Periodic traffic observed; possible C2, not confirmed|

The host logs show the account `DMEVALS\pbeesly` in relevant process and PowerShell records. The report does not reproduce authentication secrets or archive passwords from the lab material.

## Evidence Sources and Scope

|Evidence ID|Source|Reviewed data / purpose|
|---|---|---|
|E-01|OTRF Day 1 host JSON dataset|196,081 JSON records; source of Windows/Sysmon/PowerShell telemetry|
|E-02|Sysmon Event ID 1|Process creation and parent/child context, including the suspicious SCRANTON executable and NASHUA Python execution|
|E-03|Sysmon Event ID 3|Network connection metadata; 428 NASHUA records, including 348 associated with NASHUA `python.exe`|
|E-04|Sysmon Event IDs 11 and 23|File creation and deletion/shredding evidence on SCRANTON and NASHUA|
|E-05|Sysmon Event ID 18|Named-pipe activity, including PsExec-related pipe names|
|E-06|PowerShell Operational Event IDs 4103 and 4104|Script-block text and module logging for archive creation, file enumeration, and related commands|
|E-07|SCRANTON PCAP|WebDAV, SMB/PsExec, and TLS packet-level observations|
|E-08|NASHUA PCAP|Network behavior associated with NASHUA host activity|
|E-09|Analyst-extracted `OfficeSupplies.7z` contents|Archive contents and a SHA-256 comparison for `monkey.png`; original extracted binaries are not included here|

This repository intentionally excludes the original JSONL, EVTX, PCAPs, executable files, archives, private-key material, and unredacted credentials.

## Investigation Timeline

### Host telemetry timeline — timestamps taken from Windows event `UtcTime`

These rows are listed in the host telemetry's UTC fields. The source also contains `EventTime`, `EventReceivedTime`, and `@timestamp`; they are not interchangeable. Preserve the original fields when reproducing the analysis.

|UTC timestamp|Host|Observation|Evidence|
|---|---|---|---|
|2020-05-02 03:04:23.681Z|SCRANTON|PowerShell created `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\hostui.lnk`. The target was not recovered.|Sysmon ID 11|
|2020-05-02 03:08:03.948Z|SCRANTON|PowerShell Script Block Logging records the `OfficeSupplies.7z` collection/compression and WebDAV-copy script.|PowerShell ID 4104|
|2020-05-02 03:08:35.270Z|SCRANTON|`OfficeSupplies.7z` created under the user's Roaming profile.|Sysmon ID 11|
|2020-05-02 03:08:51.520Z|SCRANTON|`monkey.png` deleted. Analyst comparison found its SHA-256 matched the extracted `monkey.png` copy from `OfficeSupplies.7z`.|Sysmon ID 23 + analyst hash comparison|
|2020-05-02 03:15:04.135Z|NASHUA|`python.exe` creates/unpacks a PyInstaller-style temporary directory under the user's Local Temp path.|Sysmon ID 11|
|2020-05-02 03:15:05.142Z–03:18:00.874Z|NASHUA|Sysmon ID 3 records repeated network activity from `python.exe` to `192[.]168[.]0[.]4:8443`.|Sysmon ID 3|
|2020-05-02 03:16:00.205Z|NASHUA|PowerShell script block searches the user profile for selected extensions and credential-related filename patterns, then invokes `Compress-Archive` to create `%APPDATA%\working.zip`.|PowerShell ID 4104 / 4103|
|2020-05-02 03:16:01.393Z|NASHUA|`Compress-Archive` reports completion. The Module Logging records show four matched source paths: `Microsoft Edge.lnk`, `Bing.url`, `Links\Desktop.lnk`, and `Links\Downloads.lnk`.|PowerShell ID 4103|
|2020-05-02 03:16:19.462Z|NASHUA|`Rar.exe` runs with the Roaming `working.zip` as input and creates a second archive file at the Desktop path. Password option redacted.|Sysmon ID 1 / ID 11|
|2020-05-02 03:16:52.587Z|NASHUA|SDelete shreds `C:\Windows\Temp\Rar.exe`.|Sysmon ID 23|
|2020-05-02 03:17:41.353Z|NASHUA|SDelete shreds `C:\Users\pbeesly\Desktop\working.zip`. No matching deletion event for the Roaming `working.zip` was found in the reviewed extract.|Sysmon ID 23|
|2020-05-02 03:17:52.009Z|NASHUA|`cmd.exe` deletes `sdelete64.exe`.|Sysmon ID 23|
|2020-05-02 03:17:59.328Z–03:17:59.468Z|NASHUA|Python temporary extraction files are removed during cleanup.|Sysmon ID 23|

### PCAP timeline — kept separate from host timestamps

The PCAP packet times are presented as recorded in the analyst's Wireshark notes. They have **not** been normalized to the host event timeline.

|PCAP time (as recorded)|Source → destination|Observation|Assessment|
|---|---|---|---|
|2020-04-30 00:32 onward (HTTP server `Date` headers in the reviewed stream)|`10[.]0[.]1[.]4` → `192[.]168[.]0[.]4:80`|WebDAV discovery/authentication, metadata requests, and transfer of `OfficeSupplies.7z`. The file PUT carried `Content-Length: 1082089`; server response was `204 No Content`.|Strong evidence of successful upload to WebDAV; external exfiltration not established|
|2020-04-30 02:15:18–02:46:59|`10[.]0[.]1[.]4:60646` → `192[.]168[.]0[.]5:443`|Approximately 17,298 packets over TLS 1.2; analyst noted a recurring exchange roughly every eight seconds. Certificate metadata included `Conn and Sons` and `parse[@]conn[.]sons[.]info`.|Suspicious periodic TLS activity; C2 not confirmed|
|2020-04-30 02:35:25|`10[.]0[.]1[.]4` → `10[.]0[.]1[.]6:445`|SMB tree connect to `\\NASHUA\ADMIN$`, followed by creation, write, and close operations for `Temp\python.exe`. The reported file size was 5,305,104 bytes.|Strong evidence of lateral tool transfer|
|2020-04-30 02:40:22–02:40:43|`10[.]0[.]1[.]4` → `10[.]0[.]1[.]6:445`|SMB `ADMIN$` access and `PSEXESVC.exe` creation; `svcctl`, `OpenSCManager2`, and `CreateServiceW` requests follow. PsExec named pipes include `PSEXESVC-SCRANTON-...-stdin/stderr/stdout`.|Strong evidence of PsExec-style remote service execution|
|2020-04-30 02:35:25 onward (WebDAV object review)|`192[.]168[.]0[.]4:80` → SCRANTON|WebDAV metadata for `python.exe` reports a size of 5,305,104 bytes and type `application/x-msdownload`; the packet extraction reviewed by the analyst contained only about 717,584 bytes (approximately 13.5%).|Partial object; its exported hash is not suitable for comparison or reputation assessment|

### Timestamp caveat

OTRF's Day 1 README lists archive metadata labels for the host and network packages, while the local host JSON filename and the event/packet timestamps contain other date values. These labels are not proof of the actual event time. The available notes also show a consistent four-hour difference between example host `EventTime` and `UtcTime` fields, but that does not resolve the PCAP-versus-host discrepancy. This report therefore keeps host and packet timelines separate rather than forcing an artificial offset.

## Key Findings

### F-001 — Suspicious executable launch on SCRANTON

Sysmon Event ID 1 records execution of a `.scr` file from `C:\ProgramData\victim\...` on SCRANTON (PID 8524; the process name contains a Unicode/right-to-left marker in the exported text). The parent process was `explorer.exe`. Subsequent process and PowerShell activity was investigated as part of the same host-side chain.

**Assessment:** High confidence that the suspicious `.scr` process executed in the emulated scenario. The exact rendered filename should be preserved from raw telemetry because the text export has an encoding/Unicode presentation issue.

### F-002 — PowerShell interacted with `monkey.png` as a data carrier

The SCRANTON process investigation recorded PowerShell logic that opened `monkey.png`, extracted data from image pixel values, reconstructed text, and passed it to `IEX`. The analyst later extracted `monkey.png` from `OfficeSupplies.7z` and reported SHA-256 `A24BC4C50C379A50DF193FC747A70E5F3F66A40007635858EF2A755FA86244E8`, matching the hash recorded in the Sysmon file-deletion event for the SCRANTON copy.

This hash match links the extracted archive copy to the deleted host file. The report does not claim that the image alone proves what the reconstructed script ultimately did; that requires full script-block/process correlation.

**Assessment:** Strong support for the use of the image as a script/data carrier; exact downstream payload behavior remains bounded by the reviewed evidence.

### F-003 — Collection, archive creation, and WebDAV upload from SCRANTON

PowerShell Script Block Logging records a command sequence that compresses files from the user's Downloads directory into `%APPDATA%\OfficeSupplies.7z`, using a password-protected 7-Zip command, maps `\\192[.]168[.]0[.]4\webdav` as a temporary PowerShell drive, and copies `OfficeSupplies.7z` to that share.

The SCRANTON PCAP contains WebDAV authentication and a `PUT` request for `/webdav/OfficeSupplies.7z`. The full upload request carried `Content-Length: 1082089`, and the server returned `204 No Content`. The analyst extracted the archive and reported SHA-256 `3945D9AE1FFC7892638FFB9F3C0457E7E981EECBD6AFD6855303E64BDFCBBA77`. The extracted archive contents included a SysinternalsSuite directory and files such as `monkey.png`, `gvhxdpgd.ay1.pfx`, and `mmlrnkci.duw.bnp`.

The WebDAV service is hosted on a private address in the supplied capture. The reviewed evidence does not establish who controlled that service or whether the upload crossed an organizational boundary.

**Assessment:** High confidence that SCRANTON staged an archive and that the WebDAV server accepted the upload. Whether this should be classified as external exfiltration depends on the unknown role of the destination server.

### F-004 — Lateral tool transfer and PsExec-style execution from SCRANTON to NASHUA

The PCAP shows SCRANTON (`10[.]0[.]1[.]4`) connecting to NASHUA (`10[.]0[.]1[.]6`) over SMB/445 and accessing `\\NASHUA\ADMIN$`. SMB operations create, write, and close `Temp\python.exe`. A later sequence creates `PSEXESVC.exe` and invokes Service Control Manager operations, including `OpenSCManager2` and `CreateServiceW`. Named pipes include `PSEXESVC-SCRANTON-...-stdin`, `-stdout`, and `-stderr`.

NASHUA host telemetry subsequently records `python.exe` and its PowerShell child activity. The exported SMB object for `python.exe` was incomplete in the analyst's extraction (approximately 717,584 of 5,305,104 bytes). No hash derived from that partial object is treated as a valid full-file hash.

**Assessment:** High confidence in a SCRANTON-to-NASHUA tool transfer and PsExec-style remote service execution sequence. `ADMIN$` access demonstrates use of an administrative share but does not, by itself, establish Domain Admin group membership.

### F-005 — NASHUA file discovery, archive creation, and cleanup

PowerShell Event ID 4104 records a recursive search under the user's profile for extensions and filename patterns associated with documents, archives, pictures, links, and possible credentials. Event ID 4103 shows four paths returned in the reviewed output: `Desktop\Microsoft Edge.lnk`, `Favorites\Bing.url`, `Links\Desktop.lnk`, and `Links\Downloads.lnk`.

The script passed the returned paths to `Compress-Archive`, creating `%APPDATA%\working.zip`. Module Logging records the archive operation reaching 100% and completing. A later PowerShell command launched `Rar.exe` with the Roaming `working.zip` as input and a Desktop `working.zip` as output; the password parameter is intentionally redacted in this report. SDelete shredded `Rar.exe` and the Desktop archive. The reviewed Sysmon Event ID 23 extract does **not** show deletion of the source `%APPDATA%\working.zip`.

No network evidence reviewed here proves that NASHUA's `working.zip` or its password-protected derivative was uploaded. It must not be conflated with SCRANTON's `OfficeSupplies.7z`.

**Assessment:** High confidence in file discovery, local archive creation, password-protected repackaging, and selected cleanup. NASHUA archive exfiltration is not established.

### F-006 — NASHUA Python network activity to `192[.]168[.]0[.]4:8443`

NASHUA Sysmon Event ID 3 contains 348 records attributed to `C:\Windows\Temp\python.exe` (PID 2172) connecting to `192[.]168[.]0[.]4:8443` over TCP. The event timestamps span approximately 03:15:05.142Z to 03:18:00.874Z in the host log extract.

Sysmon Event ID 3 records connection metadata; it does not establish the contents or purpose of the application-layer traffic. The same IP also hosted the WebDAV service on port 80, but the distinct port must be treated as a separate service.

**Assessment:** Suspicious network behavior associated with the staged Python executable; C2, file transfer, and exfiltration are not confirmed.

### F-007 — Periodic TLS communication from SCRANTON to `192[.]168[.]0[.]5:443`

The SCRANTON capture contains a long TLS 1.2 communication from `10[.]0[.]1[.]4:60646` to `192[.]168[.]0[.]5:443`, with approximately 17,298 packets over the interval recorded in the PCAP notes. The analyst observed periodic exchanges at roughly eight-second intervals and certificate metadata including `Conn and Sons` and `parse[@]conn[.]sons[.]info`.

A repeated interval is consistent with a beacon-like pattern but is not sufficient to establish command and control without additional correlation (process ownership, payload/size patterns, server context, or corroborating endpoint/network evidence).

**Assessment:** Suspicious TLS communication; C2 remains an investigative hypothesis.

### F-008 — Potential Startup-folder persistence via `hostui.lnk`

Sysmon Event ID 11 records creation of `hostui.lnk` in the system-wide Startup folder. A later Prefetch record references `HOSTUI.EXE`. The shortcut target and the actual relationship between the `.lnk` and executable were not established in the reviewed material.

**Assessment:** Persistence lead only. Do not report persistence as confirmed until the shortcut target and logon execution path are validated.

### F-009 — BitLocker resource strings do not prove disk encryption

PowerShell Module Logging contains `ConvertFrom-StringData` and `Import-LocalizedData` activity loading text resources from `BitLocker.psd1`. The reviewed records show localized messages and strings used by the BitLocker module; they do not show a command such as `Enable-BitLocker`, `manage-bde`, or another confirmed volume-encryption operation.

**Assessment:** No BitLocker volume encryption is established by these records. This is not evidence of ransomware by itself.

## MITRE ATT&CK Mapping

The mappings below describe observed behaviors. They are not actor attribution and do not imply that every technique succeeded beyond what the evidence supports.

|Tactic|Technique|Name|Evidence / confidence|
|---|---|---|---|
|Execution|[T1059.001](https://attack.mitre.org/techniques/T1059/001/)|PowerShell|PowerShell Script Block and Module Logging on SCRANTON and NASHUA. **High**|
|Collection|[T1005](https://attack.mitre.org/techniques/T1005/)|Data from Local System|Recursive file enumeration and selection of local user-profile files. **Supported**|
|Collection|[T1560.001](https://attack.mitre.org/techniques/T1560/001/)|Archive via Utility|`Compress-7Zip`, `Compress-Archive`, and `Rar.exe` archive operations. **High**|
|Collection|[T1074.001](https://attack.mitre.org/techniques/T1074/001/)|Local Data Staging|`OfficeSupplies.7z` and `working.zip` created in local user-profile directories before transfer/cleanup. **High**|
|Lateral Movement|[T1021.002](https://attack.mitre.org/techniques/T1021/002/)|SMB/Windows Admin Shares|SMB access to `ADMIN$` on NASHUA. **High**|
|Lateral Movement|[T1570](https://attack.mitre.org/techniques/T1570/)|Lateral Tool Transfer|`python.exe` transferred from SCRANTON to NASHUA over SMB. **High**|
|Execution|[T1569.002](https://attack.mitre.org/techniques/T1569/002/)|Service Execution|PsExec service creation/control through `PSEXESVC.exe` and `CreateServiceW`. **High**|
|Command and Control / Transfer|[T1105](https://attack.mitre.org/techniques/T1105/)|Ingress Tool Transfer|WebDAV-hosted `python.exe` was inspected/downloaded in the SCRANTON capture; the source server's ownership and trust boundary are unknown. **Supported, context-limited**|
|Persistence|[T1547.001](https://attack.mitre.org/techniques/T1547/001/)|Registry Run Keys / Startup Folder|`hostui.lnk` created in the Startup folder; target and successful autorun not established. **Potential only**|

No ATT&CK Exfiltration technique is assigned. The WebDAV upload is a confirmed file transfer to a private-address endpoint, but the destination's ownership and its location relative to the emulated victim environment are unknown. No C2 technique is assigned to the TLS sessions because their purpose remains unconfirmed.

## Alert / Activity Triage

This case was investigated from endpoint and network telemetry rather than a supplied IDS-alert queue. The following activity was retained as suspicious or contextual:

|Activity|Disposition|Reason|
|---|---|---|
|`.scr` execution from `C:\ProgramData\victim\...`|Suspicious|Execution from a victim-named directory, followed by unusual PowerShell activity.|
|PowerShell image-pixel extraction and `IEX`|Suspicious|Reconstructs and executes text derived from image data; full downstream payload is not reproduced here.|
|WebDAV PUT of `OfficeSupplies.7z`|Confirmed transfer; intent depends on destination|HTTP request and successful `204 No Content` response establish server acceptance, not external exfiltration by themselves.|
|SMB `ADMIN$` and PsExec service creation|Suspicious / high confidence lateral movement|File transfer plus service-control sequence and PsExec named pipes.|
|NASHUA Python → `192[.]168[.]0[.]4:8443`|Suspicious / unresolved|Repeated Sysmon connections, but no application payload or transfer purpose established.|
|SCRANTON TLS → `192[.]168[.]0[.]5:443`|Suspicious / unresolved|Long TLS communication with periodic exchanges; no process attribution or decoded payload.|
|`hostui.lnk` in Startup|Potential persistence|Shortcut target and actual execution path not recovered.|
|BitLocker localized resource loading|Not evidence of encryption|No volume-encryption command or confirmed state change in the reviewed records.|

## Indicators of Compromise

See [`iocs.md`](iocs.md) for defanged indicators and supporting artifacts. No full `python.exe` hash is reported because the reviewed extracted object was incomplete.

## Limitations

- The source dataset is a controlled emulation. The case label does not prove that a real APT29 actor performed the activity.
- Host event timestamps and PCAP packet timestamps have not been reliably normalized to one common clock. Their timelines are kept separate.
- `192[.]168[.]0[.]4` is a private-address endpoint. The reviewed evidence does not prove whether it was attacker-controlled, infrastructure internal to the emulation, or a separate lab service.
- A successful WebDAV upload is established, but external data exfiltration is not. Server-side context is missing.
- `working.zip` on NASHUA is not proven to be the same archive as `OfficeSupplies.7z` on SCRANTON. No upload of the NASHUA archive is established.
- The exported SMB `python.exe` object was incomplete. Its partial hash is not a valid substitute for the full file hash.
- The TLS payloads were not decrypted. The periodic pattern is not sufficient by itself to confirm C2.
- The Startup shortcut's target was not recovered; persistence remains a hypothesis.
- BitLocker resource strings do not establish disk encryption.
- The user account is present in event context, but no broader conclusion about the interactive user or privilege-group membership is made.
- Archive passwords, WebDAV credentials, and PsExec password arguments were present in the lab material and are deliberately not reproduced.

## Verdict

**Verdict:** Suspicious multi-host activity consistent with a controlled intrusion emulation. The evidence supports a SCRANTON execution/PowerShell stage, local data collection and archiving, an accepted WebDAV upload, and lateral transfer/execution on NASHUA via SMB/PsExec. NASHUA then performed additional file discovery, local archive creation, and cleanup.

**Confidence:** High for the observed SMB/PsExec sequence and successful WebDAV object upload; high for NASHUA's PowerShell collection/archive behavior; medium for the image-carrier interpretation; low-to-moderate for TLS C2 and Startup-folder persistence.

**Not established:** APT29 attribution, the ownership/externality of the WebDAV server, confirmed C2, external exfiltration of NASHUA data, ransomware behavior, or BitLocker volume encryption.

## Recommendations

1. In a real incident, preserve endpoint telemetry, PCAPs, service-install records, and the WebDAV server logs before cleanup or remediation.
2. Identify the owner and role of `192[.]168[.]0[.]4` and validate the server-side `OfficeSupplies.7z` object against the client-side archive and its reported hash.
3. Review the complete `python.exe` object from the original source, verify its Authenticode signature and full SHA-256, and correlate it with process-creation and service-install records on NASHUA.
4. Review System Event ID 7045 and Security Event ID 4697 (where available), service configuration, and the full PsExec request/response sequence to validate service creation and execution.
5. Recover the target of `hostui.lnk`, inspect `HOSTUI.EXE`, and verify whether a logon event actually launched it.
6. Correlate the two TLS destinations with process telemetry, DNS, proxy, firewall, and server-side logs before classifying either as C2.
7. Determine whether NASHUA's Roaming `working.zip` or Desktop derivative was transferred elsewhere. Do not infer exfiltration from local archive creation and deletion alone.
8. Treat credentials embedded in scripts or command lines as exposed lab secrets: redact them from public artifacts and rotate them in any environment where they may have been reused.

## References

- [OTRF — APT29 Evals Detection Hackathon](https://github.com/OTRF/detection-hackathon-apt29)
- [OTRF — Day 1 dataset README](https://github.com/OTRF/detection-hackathon-apt29/blob/master/datasets/day1/README.md)
- [MITRE ATT&CK — PowerShell (T1059.001)](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK — Archive via Utility (T1560.001)](https://attack.mitre.org/techniques/T1560/001/)
- [MITRE ATT&CK — Local Data Staging (T1074.001)](https://attack.mitre.org/techniques/T1074/001/)
- [MITRE ATT&CK — SMB/Windows Admin Shares (T1021.002)](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK — Lateral Tool Transfer (T1570)](https://attack.mitre.org/techniques/T1570/)
- [MITRE ATT&CK — Service Execution (T1569.002)](https://attack.mitre.org/techniques/T1569/002/)
- [MITRE ATT&CK — Ingress Tool Transfer (T1105)](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK — Startup Folder (T1547.001)](https://attack.mitre.org/techniques/T1547/001/)
