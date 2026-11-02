# REMnux validation, November 1, 2026

The official `remnux/remnux-distro:noble` image was installed and tested using
registry digest `sha256:880089abf02feb5240607545ab601e2d97d7b1c213d6341aa2e7ce356f65c8c2`.
The Ward runner uses offline disposable containers with 2 GiB memory, one CPU,
64 processes, and a 120-second outer deadline. Sample bytes pass over stdin;
no host folders or management socket are mounted.

## Live controls

A harmless 28-byte text fixture was correctly identified as ASCII text.
PE-specific tools were marked not applicable.

The Windows `whoami.exe` control, SHA-256
`23240ef9f8b0a9a324110b1c2331de31dc1b0e08f5359cb707e51a939af56cd3`,
completed file identification, pefile 2024.8.26 parsing, and capa 9.3.1 static
analysis. capa returned twelve capabilities. This is a useful negative control:
capabilities such as token inspection and process operations also occur in
legitimate software and do not establish maliciousness.

## Known malicious artifact

Source: [Built.exe at commit 451f057](https://github.com/sjyjoghkkjj/Discord-Nitro-Generator/blob/451f057fa9c67739e37b8bcff2db7e2094e8c982/Built.exe).

- Size: 7,967,908 bytes.
- SHA-256: `4a5cdd67f46c92c5d00495057c7715457bef4fcd5d8915a0239018142d8101f2`.
- Vendor evidence: [exact VirusTotal report](https://www.virustotal.com/gui/file/4a5cdd67f46c92c5d00495057c7715457bef4fcd5d8915a0239018142d8101f2).
- file identified a 64-bit Windows GUI PE with seven sections.
- pefile completed headers, imports, and section entropy analysis.
- Detect It Easy identified the PyInstaller overlay, Visual C/C++ compiler,
  Microsoft linker, and Authenticode data. Signature presence does not establish
  signature validity, trusted provenance, or safety.
- Ward's separate existing archive parser identified `blank.aes`, `rar.exe`,
  and `rarreg.key`. These names were not independently decrypted or executed
  by this REMnux run.
- Final report coverage: partial. Behavioral analysis: not run.
- Original report digest: `sha256:e05cb0e4a62e095caf0094a7068f939cb89eb53deeff24a85065c66c95fffb62`.

Before the final packed-file policy was selected, capa's full analysis hit the
60-second limit, and its pefile-only backend raised NotImplementedError. A prior
1-GiB attempt exited with signal 9; that signal alone does not establish the
cause. These attempts supplied no payload behavior evidence. The final worker
performs packer analysis on detected PyInstaller bundles and explicitly skips
native capability analysis pending unpacking.

## Integration limits

The operator command is `ward remnux FILE --sha256 EXPECTED_HASH`. It produces
JSON bound to the artifact and image digests. It does not launch malware, claim
the Verified tier, or automatically publish its report. The public service
continues to use Ward's static engine; REMnux is an installed operator tier.

No sample bytes were retained in this repository, and no customer or third-party
system was tested. The known sample was retrieved from its pinned public GitHub
artifact and read as data inside the analysis container.
