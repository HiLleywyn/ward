# If you ran a suspicious emulator download

Do not panic, but treat saved passwords and active sessions as potentially
exposed until you know what happened.

## From a different, trusted device

1. Change the password for your primary email account.
2. Revoke active email sessions and verify recovery addresses and forwarding
   rules.
3. Change passwords and revoke sessions for password managers, banking,
   cryptocurrency, Steam, Epic, PlayStation, Xbox, Discord, GitHub, and other
   accounts used on the affected computer.
4. Rotate developer tokens, SSH keys, API keys, and browser-saved credentials.
5. Turn on multi-factor authentication with a new recovery-code set.

## On the affected computer

1. Disconnect it from Wi-Fi and Ethernet.
2. Photograph or record unexpected Microsoft Defender exclusions before
   changing them, if you can do so safely.
3. Preserve the download URL, filename, and SHA-256. Do not open the file again.
4. Run Microsoft Defender Offline or another trusted offline scanner.
5. Review recently installed programs, scheduled tasks, startup entries,
   browser extensions, and security exclusions.
6. If an information stealer is plausible, rebuild the system from trusted
   installation media. A clean scan alone cannot prove every persistence method
   or stolen session was recovered.

## Evidence to save

- the full repository and release URLs;
- the owner and repository names;
- release tag, asset name, size, and SHA-256;
- download time and browser history entry;
- antivirus detection name and timestamp;
- unexpected Defender exclusions;
- account-login alerts received after execution.

Do not post tokens, passwords, personal files, or live malware links in a public
issue. Use the project or platform's private security channel.

