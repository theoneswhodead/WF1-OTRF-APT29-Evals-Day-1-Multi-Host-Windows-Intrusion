# W-F1 — OTRF APT29 Evals Day 1 | Windows Intrusion Investigation

SOC L1 / DFIR-style investigation of the OTRF APT29 Evals Day 1 host telemetry and network captures.

> **Lab exercise only.** This repository documents a controlled adversary-emulation dataset. It does not describe a real-world incident, establish APT29 attribution, or claim that every observed suspicious action succeeded.

## Executive findings

- **SCRANTON** (`10[.]0[.]1[.]4`) executed a suspicious `.scr` file and subsequent PowerShell activity. The reviewed PowerShell logic extracted content from `monkey.png` and passed reconstructed content to `IEX`.
- PowerShell created `OfficeSupplies.7z` from files in the Downloads directory. A PCAP review shows a `PUT` of `OfficeSupplies.7z` to an internal WebDAV endpoint (`192[.]168[.]0[.]4:80`) with `Content-Length: 1082089`, followed by HTTP `204 No Content`. This confirms that the WebDAV server accepted the upload; it does **not** prove that the endpoint was external to the lab environment.
- **SCRANTON → NASHUA** (`10[.]0[.]1[.]6`) lateral movement is strongly supported by SMB access to `ADMIN$`, transfer of `Temp\python.exe`, and PsExec service-control activity (`PSEXESVC.exe`, `svcctl`, `OpenSCManager2`, `CreateServiceW`).
- On NASHUA, `python.exe` launched PowerShell. The script searched the user profile for document-, archive-, image-, shortcut-, and credential-related file patterns, then created `%APPDATA%\working.zip`. `Rar.exe` created a password-protected archive on the Desktop; SDelete shredded the Desktop copy and selected tooling.
- NASHUA generated 348 Sysmon Event ID 3 records for `python.exe` connecting to `192[.]168[.]0[.]4:8443`. The application-layer purpose and transferred content were not established.
- A separate periodic TLS connection from SCRANTON to `192[.]168[.]0[.]5:443` is suspicious and worth retaining as a lead, but C2 is **not confirmed**.
- PowerShell records referencing `BitLocker.psd1` show localized module-resource loading. No BitLocker enablement or volume-encryption operation was established.

## Repository contents

- [`incident-report.md`](incident-report.md) — executive summary, affected hosts, findings, split timelines, ATT&CK mapping, limitations, verdict, and recommendations.
- [`iocs.md`](iocs.md) — defanged network indicators, file hashes, supporting artifacts, and excluded/unconfirmed items.

## Investigation scope

The analysis used the OTRF Day 1 host event dataset and the SCRANTON/NASHUA packet captures. Host-side review included Sysmon Event IDs 1, 3, 11, 18, and 23, plus PowerShell Operational Event IDs 4103 and 4104. The source host dataset contained 196,081 JSON records. The NASHUA Event ID 3 extract contained 428 records, including 348 associated with `C:\Windows\Temp\python.exe`.

The report keeps Windows event timestamps and PCAP timestamps in separate timelines. The source material exposes multiple timestamp fields and archive metadata labels; a reliable common clock offset was not established. Do not use the two timelines as if they were fully synchronized.

## Source material

- [OTRF — APT29 Evals Detection Hackathon (May 2, 2020)](https://github.com/OTRF/detection-hackathon-apt29)
- [OTRF — Day 1 dataset README](https://github.com/OTRF/detection-hackathon-apt29/blob/master/datasets/day1/README.md)
- [OTRF — Security Datasets](https://github.com/OTRF/Security-Datasets)

The original host dataset and PCAPs are **not** redistributed in this repository. Obtain them from the source project and retain their original hashes separately.

## Tools and methods

- Sysmon and Windows PowerShell Operational logs
- Event extraction and filtering with PowerShell/Python scripts
- Wireshark for SMB, HTTP/WebDAV, TCP, and TLS inspection
- SHA-256 comparison for the extracted `monkey.png` artifact
- MITRE ATT&CK for behavioral mapping

## Important caveats

- The successful WebDAV upload is supported by an HTTP `PUT` followed by `204 No Content`. Whether the destination was attacker-controlled or outside the exercise network is not established by the reviewed evidence.
- The `OfficeSupplies.7z` archive from SCRANTON is **not** assumed to be the same artifact as NASHUA's `working.zip`.
- The exported `python.exe` object from SMB was incomplete (approximately 13.5% of the reported 5,305,104-byte file in the reviewed extraction). A hash of that partial object must not be used for reputation conclusions.
- The Startup-folder `hostui.lnk` is a persistence lead, not proof that persistence succeeded. Its target was not established.
- No ransomware, BitLocker volume encryption, confirmed C2, or NASHUA data exfiltration conclusion is made.
- Passwords and authentication secrets present in the original lab script/logs are intentionally omitted. PsExec password arguments and archive passwords must remain redacted in any public copy.
- Raw JSONL, EVTX, PCAP, extracted executables, certificate/private-key material, and original archives should remain outside the public repository.

**Lab only:** Defanged indicators are supplied for safe presentation. Validate context before creating block rules in a real environment.
