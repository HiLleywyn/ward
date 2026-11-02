# Security and privacy

Report a vulnerability in Ward through a private GitHub security advisory in
this repository. Avoid public reports containing credentials or personal data.

Ward clones public HTTPS Git repositories, hashes bounded content, parses
supported text and nested archives, and may send a repository snapshot plus up to two binaries to
its isolated analysis workers. The public web container never executes
submitted content and has no Docker management socket. REST file submission is
transient and the browser interface has no upload control.

The public deployment hides local scan history, uses no personal GitHub token,
a bounded queue, limits concurrent work, and stores state in
a dedicated volume. The application runs without root privileges on a read-only
filesystem with dropped Linux capabilities.

The REMnux controller is trusted infrastructure with Docker access, no network,
and fixed child-container arguments. Samples are treated as data in disposable
offline children. The optional Windows host worker advertises availability only
after a benign Windows Sandbox launch and teardown succeeds; sample execution
then occurs in a new networkless Sandbox with only job-specific transfer
folders. Both tiers remain partial analysis and never imply safety.

Malware repository records describe historical paths named by cited primary
research. Current availability does not prove the contents of a changed object.
Unverified community submissions remain UNKNOWN until reviewed.

There is no guarantee that a file without a known indicator is safe. Malware
identification and software provenance are different claims.
