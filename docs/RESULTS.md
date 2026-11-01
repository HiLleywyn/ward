# Reviewed repository record

FAIL identifies a repository named in a primary malware report at the stated
date. It is a historical path warning. It does not identify a real person or
establish the behavior of a future owner of the same path.

UNKNOWN is the result for heuristic detections, unreviewed community reports,
and checks that found no known indicator. PASS is reserved for a specific
reviewed test with a stated revision and scope, such as provenance verification.
It never means software is guaranteed safe.

The machine-readable source of this record is
[repositories.json](../src/emuwatch/advisories/repositories.json).
The local interface displays it alongside recent observations. Every scan and
community lead is appended to a local SQLite history at `.emuwatch` in your
user directory. Set `EMUWATCH_STATE_DIR` to select another location.

| Result | Campaign | Named repositories | Primary report |
| --- | --- | ---: | --- |
| FAIL | Minecraft Stargazers | 5 | [Check Point](https://research.checkpoint.com/2025/minecraft-mod-malware-stargazers/) |
| FAIL | Webrat fake exploits | 15 | [Kaspersky](https://securelist.com/webrat-distributed-via-github/118555/) |
| FAIL | GitVenom | 1 | [Kaspersky](https://securelist.com/gitvenom-campaign/115694/) |
| FAIL | Yoba fake AI apps | 4 | [Check Point](https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/) |
| UNKNOWN | PS5 impersonation | 0 confirmed in this investigation | [Reported campaign](../src/emuwatch/advisories/campaigns.json) |

These campaigns have different sources and timelines. No relationship between
the PS5 operation and the other campaigns has been established.

Community leads can be filed through the repository's issue form once hosted,
or locally with:

```powershell
emuwatch report OWNER/REPO --evidence https://example.org/report --description "Observed behavior"
emuwatch history
```

Reports cannot assign their own confirmed status. Corrections to reviewed data
go through a normal reviewed change, retaining Git history. Local observations
retain their original result when later evidence changes an assessment.
