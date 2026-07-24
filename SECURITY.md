# Security

firmcarve is meant to be pointed at firmware nobody vouches for, so a crash, a hang, a read
outside the buffer or a file written outside `extract_dir` is a security bug.

| version | fixes |
|---|---|
| latest 1.x | yes |
| 0.x | no |

Report it privately through GitHub's "Report a vulnerability" on this repository, with the input
that triggers it if you can share it. Expect an answer within a week.
