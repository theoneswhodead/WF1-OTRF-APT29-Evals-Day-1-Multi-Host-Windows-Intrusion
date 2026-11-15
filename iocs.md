W-F1 — APT29 Evals Day 1: IOCs and Network Artifacts
All network indicators are defanged for safe presentation. Internal lab endpoints, supporting artifacts, and suspicious indicators are separated. An observed endpoint or tool is not automatically malicious.
Primary suspicious network indicators
Type	Indicator	Context	Confidence / handling
IPv4 + port	192[.]168[.]0[.]4:80	Apache WebDAV endpoint serving /webdav/; accepted a PUT for OfficeSupplies.7z and also exposed python.exe metadata/content.	High confidence as an observed file-transfer endpoint; destination ownership and externality unknown. Do not treat as a public C2 IP.
URL	hxxp://192[.]168[.]0[.]4/webdav/OfficeSupplies[.]7z	WebDAV upload path for OfficeSupplies.7z; full upload recorded Content-Length: 1082089, followed by HTTP 204 No Content.	High confidence as an observed upload URL. Exfiltration beyond the lab boundary is not established.
IPv4 + port	192[.]168[.]0[.]4:8443	Destination of 348 NASHUA Sysmon Event ID 3 records attributed to python.exe PID 2172.	Suspicious / unresolved. Application-layer purpose and payload not established.
IPv4 + port	192[.]168[.]0[.]5:443	SCRANTON TLS 1.2 communication from 10[.]0[.]1[.]4:60646; approximately 17,298 packets and recurring exchanges noted at roughly eight-second intervals.	Suspicious / possible beaconing. C2 is not confirmed.


File hashes
Type	SHA-256	File / context	Confidence / handling
SHA-256	3945D9AE1FFC7892638FFB9F3C0457E7E981EECBD6AFD6855303E64BDFCBBA77	OfficeSupplies.7z — hash reported by the analyst for the extracted archive copies.	Analyst-reported; the original binary is not included in this repository for independent recalculation.
SHA-256	A24BC4C50C379A50DF193FC747A70E5F3F66A40007635858EF2A755FA86244E8	monkey.png — extracted archive copy; analyst reported that it matches the hash in the SCRANTON Sysmon Event ID 23 record.	Strong file-identity correlation. Treat as a related artifact, not a standalone malicious-file verdict.


No full-file hash is provided for python.exe. The reviewed SMB extraction was incomplete (about 717,584 bytes of a reported 5,305,104 bytes); a hash calculated from that fragment would not identify the original file.
Internal host context — not external block indicators
Type	Indicator	Context
Internal IPv4	10[.]0[.]1[.]4	SCRANTON; suspicious .scr execution, PowerShell, archive creation, WebDAV upload, and SMB/PsExec source.
Internal IPv4	10[.]0[.]1[.]6	NASHUA; receives python.exe, runs PsExec service/Python/PowerShell, creates working.zip, and connects to 192[.]168[.]0[.]4:8443.
Internal IPv4	10[.]0[.]0[.]4	NEWYORK; observed in domain-related SMB/IPC$, SYSVOL, LDAP/Kerberos context. No evidence identifies it as the attacker.
Internal hostname	SCRANTON[.]dmevals[.]local	Hostname associated with 10[.]0[.]1[.]4.
Internal hostname	NASHUA[.]dmevals[.]local	Hostname associated with 10[.]0[.]1[.]6.
Internal hostname	NEWYORK[.]dmevals[.]local	Hostname associated with 10[.]0[.]0[.]4.


Supporting network and certificate artifacts
Type	Artifact	Context	Handling
HTTP method / path	PUT /webdav/OfficeSupplies.7z	WebDAV archive upload from SCRANTON.	Strong behavioral evidence; the path is not a standalone IOC.
HTTP response	204 No Content	Response after the full OfficeSupplies.7z PUT.	Confirms server acceptance of the request.
HTTP server	Apache/2.4.37 (Unix)	WebDAV service response on 192[.]168[.]0[.]4:80.	Supporting infrastructure detail.
HTTP User-Agent	Microsoft-WebDAV-MiniRedir/10.0.18362	Windows WebDAV client observed during WebDAV activity.	Supporting artifact, not malicious by itself.
WebDAV auth username	cozy	Username visible in Digest authentication exchange.	Credential-related context; not an IOC. Do not publish passwords or Digest response values.
TLS certificate organization	Conn and Sons	Certificate metadata observed for the SCRANTON TLS session to 192[.]168[.]0[.]5:443.	Contextual certificate attribute; not an independent malicious indicator.
TLS certificate IA5 string	parse[@]conn[.]sons[.]info	Certificate metadata associated with the SCRANTON TLS session.	Defanged certificate string; not confirmed DNS resolution or a verified mailbox.
TLS certificate organization	Rempel Group	Certificate metadata observed for a TLS service at 192[.]168[.]0[.]4.	Contextual certificate attribute.
TLS certificate IA5 string	synthesize[@]rempel[.]group[.]net	Certificate metadata associated with the 192[.]168[.]0[.]4 service.	Defanged certificate string; not confirmed DNS resolution or a verified mailbox.


Host-based artifacts — not standalone IOCs
Type	Artifact	Context	Handling
File	OfficeSupplies.7z	SCRANTON archive created from Downloads and uploaded to WebDAV.	Generic filename; correlate with its SHA-256 and transfer context.
File	monkey.png	SCRANTON image used by PowerShell pixel/data extraction logic; matching copy found in OfficeSupplies.7z.	Carrier/artifact; hash is useful for correlation, not an independent verdict.
File	python.exe	Downloaded/observed via WebDAV and transferred to NASHUA C:\Windows\Temp\python.exe.	Common filename. Verify full binary hash/signature before blocking.
File	PSEXESVC.exe	PsExec service component observed during SMB remote execution.	Legitimate Sysinternals component; context makes its use suspicious.
File	Rar.exe	Used on NASHUA to create a password-protected archive.	Dual-use utility; not malicious by itself.
File	sdelete64.exe	Used to shred selected files and tooling on NASHUA; also present in SysinternalsSuite on SCRANTON.	Legitimate Sysinternals utility; behavior and context matter.
File	hostui.lnk	Created in SCRANTON's system-wide Startup folder. Target not recovered.	Potential persistence artifact; unconfirmed.
File	hostui.exe	Prefetch artifact observed after hostui.lnk creation.	Relationship to the shortcut is unconfirmed.
File	gvhxdpgd.ay1.pfx	PFX file listed in extracted OfficeSupplies.7z contents.	Potentially sensitive certificate/key artifact; contents and purpose not analysed. Do not publish the file itself.
File	mmlrnkci.duw.bnp	File listed in extracted OfficeSupplies.7z contents.	Unknown artifact; file type and purpose not established.


Excluded / not confirmed as malicious indicators
- 10[.]0[.]0[.]4 (NEWYORK) is not listed as an attacker IOC. The reviewed traffic is consistent with domain infrastructure communication; no evidence attributes the intrusion to this host.
- 192[.]168[.]0[.]4:8443 and 192[.]168[.]0[.]5:443 are investigative leads. Neither has been confirmed as C2.
- working.zip on NASHUA is not proven to be the same file as SCRANTON's OfficeSupplies.7z.
- No transfer of NASHUA's working.zip to an external destination was established.
- The BitLocker module resource strings are not evidence that a volume was encrypted.
- No valid full-file hash for the incomplete python.exe extraction is available.
- No actor attribution is made from these indicators.
Handling notes
- Keep the original PCAPs, host JSONL, EVTX, binaries, extracted archives, and source datasets outside the public GitHub repository.
- Never include the archive password, WebDAV password, PsExec -p value, Digest response values, private-key material, or unredacted command lines containing secrets.
- Validate internal lab indicators against the source capture before reuse. Private-address endpoints should not be blocked in production solely because they appear in this exercise.
- These indicators are for retrospective training and correlation, not a ready-made production blocklist.
