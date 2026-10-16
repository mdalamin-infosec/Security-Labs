# Applying the prepared cleanup

The cleanup exists on local branch `chore/portfolio-cleanup`, based on
`b87676f73be3a72de920d6805bf46f19fbb4ce36` from `master`.
GitHub publication was not completed: this session had public read access but
no authenticated Git push. No remote/default branch was modified.

The delivery ZIP includes a clean `Security-Labs/` snapshot and an incremental
`security-labs-cleanup.bundle` containing the separate commits. The source
snapshot contains no `.git` directory; importing the bundle preserves history.

## Import into your existing Git clone
First extract the delivery ZIP. In a terminal, enter your **existing Git clone**
of `mdalamin-infosec/Security-Labs`, not the snapshot directory. Ensure
`git status --short` is clean; preserve your own uncommitted work first.

Replace the bundle-path value below with its actual absolute path:
```bash
CLEANUP_BUNDLE='/absolute/path/to/security-labs-cleanup.bundle'
git bundle verify "$CLEANUP_BUNDLE"
git fetch "$CLEANUP_BUNDLE" refs/heads/chore/portfolio-cleanup
git switch -c review/security-labs-cleanup FETCH_HEAD
git log --oneline b87676f73be3a72de920d6805bf46f19fbb4ce36..HEAD
git diff --stat b87676f73be3a72de920d6805bf46f19fbb4ce36..HEAD
```

The bundle requires the base commit above. A normal existing/full clone should
contain it. If verification reports a missing prerequisite, fetch the relevant
history from your own origin before retrying. If the local review branch name
already exists, choose a new name rather than replacing it.

Review the branch and follow each project's README. Push the review branch
using your own authenticated GitHub account when ready:
```bash
git push -u origin review/security-labs-cleanup
```

Then compare it with current `master` and open a pull request in GitHub.
If `master` has advanced, review/resolve any merge conflicts on the review branch.
No force push, history rewrite, automatic merge, or replacement of your local
work is required by these instructions.

## Scope and verification
- Two Cargo `target/` trees were removed from tracking: 2,877 files and
  1,717,429,178 logical bytes at the baseline.
- Both Rust application `main.rs` files remain byte-for-byte identical.
- The five requested top-level names were already correct. Internal source,
  rules, configuration, evidence paths and package-data handling were repaired.
- No Makefiles remain; none were needed. Known third-party generated dependency
  source/binaries were removed with the build trees. Ownership review of retained
  original project code remains a personal TODO.
- All five READMEs distinguish executed checks from unmeasured results.
- 70 Python unit tests passed in the working checkout and again in an independent
  shallow clone with a separate environment. [Fresh-clone output](fresh-clone-run.txt)
  and [the original per-project records](VALIDATION.md) are retained.
- Two wheel installations were exercised outside the repository. Shell/Python/
  YAML/TOML/JSON syntax and relative document/source links were checked.
- The six legacy PNGs were preserved byte-for-byte and renamed to describe what
  they actually show. Capture-command screenshots are not alert/status evidence.
- Actual Suricata/Docker/Rust/Nmap/NVD/browser integration remains TODO. Scapy
  PCAP generation was blocked by this runtime's netlink-socket permissions.

Removing files from the current tree does not erase their old Git objects.
The bundle preserves the original history relationship. A history rewrite
would be separate, deliberately reviewed work.

[All 15 personal TODO groups](TODO.md) · [15 interview questions](INTERVIEW_QUESTIONS.md).
