# Ghost Data Still Exists - deletion audit agent

Deterministic, evidence-first audit pipeline. No LLM is required for the submitted run; one can
optionally transcribe screenshots and disambiguate intent (`--use-llm`), but every status and step
in `output.csv` comes from rules and reconstructed state, not from a model.

## Run

```bash
# from the repository root (Python 3.10+; core uses the standard library only)
python code/main.py --probe          # print real CSV headers, all rule rows, evidence file types
python code/main.py --eval           # score vs dataset/sample_output.csv + team cases; writes evaluation/evaluation_report.md
python code/main.py                  # dataset/deletion_requests.csv -> output.csv (518 rows, sorted) + evaluation/usage_report.md
python code/main.py --use-llm        # optional: pip install anthropic, ANTHROPIC_API_KEY (model via AUDIT_LLM_MODEL)
cd code && python -m unittest tests.test_agent   # unit + robustness tests
```

Optional extras for PDFs/images: `pip install pypdf pytesseract pillow` (plus the tesseract binary
for OCR). The final submitted run used NEITHER an LLM NOR OCR: 11 screenshot PNGs are listed as
unparsed in `evaluation/run_log.txt` (no tesseract in the sandbox).

## Pipeline

1. **Intent gate** (`intent.py`) - multilingual, negation-aware. Covers direct deletion phrasings,
   "remove records under both addresses", "switch off any integration that could copy them back",
   and "check/confirm the profile is gone". Non-deletion -> `NOT_APPLICABLE`, `[]`.
2. **Identity resolution** (`identity.py`) - request email -> `user_id`; collects every current and
   historical email, phone, email hash (plus sha256/sha1/md5 of each email) and name from
   `user_identities.csv` + `user_audit_log.csv`.
3. **Evidence ingestion** (`evidence.py`) - every file in `evidence_files.csv` is normalised into
   timestamped observations `(system_id, resource_id, state)` where the system id comes from file
   CONTENTS (`service=`, `data_store`, `origin_system`, table names), never from the file name:
   - SQL dumps (incl. `customer_data_*` generic stores with `record_json`, replica/primary tables);
   - JSON snapshot bundles (`snapshots[].data_store`), service resource exports (`service_exports`),
     plain record collections (analytics reports, export jobs, security ledger);
   - handover/lookup lists (`ts | system | resource | CATEGORY | RESULT | subject`);
   - kv observability and readback logs (incl. `<ts> {json}` syslog payloads), merging the subject
     tokens of a `*_started` line into its `*_completed` line via the trace id;
   - PDFs (pypdf) and OCR-able images as subject-bearing support attachments.
4. **State at `audit_at`** (`state.py`) - the newest observation per (system, resource) wins, but a
   file whose manifest `captured_at` is after `audit_at` is NEVER admissible, regardless of the
   timestamps inside it. Resources link to a user through any observed identifier (emails, phones,
   hashes, `user_id`, name). The primary profile resource, when no evidence names it, is named from
   the deletion workflow's own `DELETE_RECORD` activity - a claim used ONLY to name the resource,
   never as proof of state. A `DELETE_RECORD` activity on any resource also overrides its policy
   treatment to DELETE.
5. **Policy** (`policy.py`) - `deletion_rules.csv` keyed by data category; SUPPORT_ATTACHMENT
   (delete) vs SUPPORT_MESSAGE (redact) is decided from a category hint in the evidence.
6. **Planner** (`planner.py`, `schema.py`) - findings -> remediation -> verification, ordered as the
   problem statement requires (phase, operation-table order, `system_id`, `resource_id`); COMPLETE =
   verification-only with evidence ids; INCOMPLETE = findings with evidence ids + remediation and
   verification with empty evidence ids. Every row passes `schema.validate`.

## Layout

```
code/main.py            CLI              code/ghostaudit/   agent, identity, intent, evidence, state, policy, planner, schema, llm, reports
code/evaluation/        metrics, run_eval, synthetic cases (real schema), notes.md (failures & improvements)
code/tests/             unit + robustness tests
```

## Assumptions verified on the real data

- TRUE: state is observable in evidence (404/hit, `enabled`, `restore_allowed`, FOUND/NOT_FOUND,
  snapshot rows); reported_status / activity results are claims and are never trusted for state.
- TRUE: file admissibility at `audit_at` follows the manifest `captured_at`, not internal record times.
- FALSE (original guess): `system_id` can be derived from evidence file names -> it must come from contents.
- KNOWN LIMIT: some resources carry no participant-visible link to their user (e.g. already-nulled
  analytics profiles, profile ids present in no evidence file). Their linkage exists only in hidden
  generator truth; those steps can miss on `resource_id`. See `evaluation/notes.md`.
