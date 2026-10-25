## Failures found and improvements made

| # | Failure found | How it was found | Improvement |
|---|---|---|---|
| 1 | The original pipeline was written against a GUESSED schema: it took `system_id` from evidence file names (e.g. `service_resource_export_20260915_114455`) instead of the logical service (`account_service`), so every step's `system_id` was wrong on the real data. | `--eval` diff against `sample_output.csv` (step F1 was 0.00). | The evidence layer was rewritten to normalise every file format into `(system_id, resource_id, time, state)` observations where the system comes from file *contents* (`service=`, `data_store`, `origin_system`, table names). |
| 2 | Evidence captured AFTER a case's `audit_at` (e.g. the 2026-09-17 snapshot bundle) was used when its internal record timestamps pre-dated `audit_at`, polluting state with inadmissible observations. | Sample cases 21/27/28/29/30 had extra findings sourced from `evidence_02`. | Admissibility now uses the manifest `captured_at` of the file (per-record times only order observations inside admissible files). A unit test guards it. |
| 3 | kv-log `*_completed` lines carry the state (`rows=0`, `status_code=404`, `enabled=false`) but not the subject; the subject lives on the matching `*_started` line (`lookup_key=...`). Resources were therefore unlinked or mis-linked. | Traced missing/false resources in sample cases 09, 12, 17, 19. | Observations merge subject tokens across the trace id, so the completed line links to the same user. |
| 4 | The intent gate rejected real deletion phrasings: "Can you remove that search result too?", "switch off any integration that could copy them back", a Japanese deletion request, and "check the latest state and confirm the profile is gone". | Status mismatches on sample cases 06/10/14/17/25/26/29. | Broader multilingual DELETE_RE, a switch-off-integrations pattern, a confirm-the-deletion pattern, and negation handling restricted to ASCII text. Sample status accuracy is now 32/32. |
| 5 | SUPPORT_MESSAGE (REDACT) vs SUPPORT_ATTACHMENT (DELETE) were conflated: subject-owned attachments were proposed for redaction instead of deletion. | Sample cases 07/10/13 diffs. | Attachments carry a category hint (handover `SUPPORT_ATTACHMENT` rows, support-document PDFs, replica contact index) and follow the attachment rule. |
| 6 | `marketing_db`-style hash-only rows and `indexed_at` timestamps in SQL dumps were missed; `support_replica` was treated as its own system. | Unit tests + sample case 06/10. | `search_documents`/`indexed_at` handled, replica services normalised to their platform. |
| 7 | Analytics resource `analytics_9914` required DELETE (not the default ANONYMIZE) because the deletion workflow itself targeted it with DELETE_RECORD. | Sample case 12 diff. | A DELETE_RECORD activity on a resource now overrides its policy treatment to DELETE. |
| 8 | JSON-payload observability logs (syslog style, no key=value) were routed to the plain-document parser and produced one blob observation. | Zero observations for `structured_service_events_eu_west_20260918.log`. | Detection of `<ts> {json}` lines routes them to the kv-log parser (which flattens the JSON payload). |

### Remaining known gaps (honest)

- For some resources the participant-visible evidence does NOT contain any link to the user (e.g. an anonymized
  analytics profile whose identifiers were already nulled before any supplied capture, or a primary profile resource
  id that appears in no evidence file at all). Their linkage exists only in the generator's hidden truth. We name the
  primary profile resource from the deletion workflow's own `DELETE_RECORD` activity (used as a claim to NAME the
  resource only, never as proof of state) when no evidence names it, which can mismatch the hidden id; such steps then
  miss on `resource_id`. Sample-set impact is visible in the failures section above (e.g. case_04, case_18, case_20).
- Evidence captured only in files dated after `audit_at` is never used, per the spec; resources whose only mention is
  in such files cannot get evidence-backed steps.
- 11 screenshot PNGs (admin consoles) are not OCR'd in the final run because the sandbox has no tesseract binary and
  the run is LLM-free; they are reported in `run_log.txt` as unparsed. On a host with `pytesseract`+tesseract (or an
  LLM key) they are transcribed automatically.

### Metric sanity checks (mutation tests)
Swapping two steps in the expected answer drops exact-sequence accuracy while step-set F1 stays 1.0; changing one
`evidence_id` lowers field-level evidence accuracy; flipping one status lowers status accuracy. So each metric reacts
to the failure it is meant to measure.

### Robustness tests (`tests/test_agent.py`)
Post-audit evidence is ignored; intent gate (export vs delete vs negation); historical-email identity resolution;
COMPLETE verification-only plans with evidence ids; INCOMPLETE findings-with-evidence + empty-evidence remediation and
verification; hash-only SQL records; tombstone redaction; flow-disable before deletes; user-id renaming and row-order
reversal invariance (no hidden id dependence); step ordering rules.
