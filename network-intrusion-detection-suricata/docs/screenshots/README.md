# Existing screenshot content review

These six original PNGs were visually inspected during cleanup and preserved
byte-for-byte. Names now describe their visible content. They do not replace
the real-engine case validation in [VALIDATION.md](../VALIDATION.md).

| Current file | Former filename | What is actually visible / evidence boundary |
| --- | --- | --- |
| [01-legacy-project-tree.png](01-legacy-project-tree.png) | `01-project-structure.png` | A legacy directory tree and screenshot command; not the current layout |
| [02-screenshot-capture-command.png](02-screenshot-capture-command.png) | `02-suricata-status.png` | Screenshot-capture command; no Suricata service-status output |
| [03-rule-file-display.png](03-rule-file-display.png) | `03-custom-rules.png` | `cat` output displaying the four custom rules; not engine loading or detection |
| [04-screenshot-capture-command.png](04-screenshot-capture-command.png) | `04-fastlog-alerts.png` | Screenshot-capture command; no alert records |
| [05-screenshot-capture-command.png](05-screenshot-capture-command.png) | `05-response-mechanism.png` | Screenshot-capture command; no blocking or response result |
| [06-ping-connectivity.png](06-ping-connectivity.png) | `06-live-monitoring.png` | A two-packet ping to the example target with responses; no IDS alert or live monitoring output |

Visible content alone does not authenticate the capture's author, date,
environment or relationship to the current source. TODO: confirm provenance
and personally collect sanitized service/rule-load/alert/response evidence
after running the documented lab cases. The missing outputs were not recreated.
