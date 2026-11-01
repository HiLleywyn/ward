# Security and privacy

Report a vulnerability in Ward through a private GitHub security advisory in
this repository. Avoid public reports containing credentials or personal data.

Ward reads GitHub metadata and text. It does not execute submitted content or
download release assets. Browser file hashing uses local bytes. No upload
endpoint is provided.

The public deployment hides local scan history, uses no personal GitHub token,
caps fresh GitHub requests, limits concurrent connections, and stores state in
a dedicated volume. The application runs without root privileges on a read-only
filesystem with dropped Linux capabilities.

Malware repository records describe historical paths named by cited primary
research. Current availability does not prove the contents of a changed object.
Unverified community submissions remain UNKNOWN until reviewed.

There is no guarantee that a file without a known indicator is safe. Malware
identification and software provenance are different claims.
