# Legacy screenshot content review

These six PNGs are retained as historical project artifacts. Their filenames describe only what is visibly present; they are **not** used as the source of truth for the current live NIDS metrics.

| File | What is visibly shown | Evidence boundary |
| --- | --- | --- |
| `01-legacy-project-tree.png` | Legacy directory tree and screenshot command | Historical layout only |
| `02-screenshot-capture-command.png` | Screenshot-capture command | No Suricata status evidence |
| `03-rule-file-display.png` | Four custom rules displayed with `cat` | Source display, not engine execution |
| `04-screenshot-capture-command.png` | Screenshot-capture command | No alert record |
| `05-screenshot-capture-command.png` | Screenshot-capture command | No response/blocking result |
| `06-ping-connectivity.png` | Two-packet ping with replies | Connectivity only; no IDS alert shown |

Current detection claims come from the retained owner-run EVE/ground-truth evaluation documented in [../VALIDATION.md](../VALIDATION.md), not from these screenshots.

The images remain useful as provenance/context artifacts, but visible content alone cannot prove author, date, environment or execution state.
