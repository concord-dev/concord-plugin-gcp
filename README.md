# concord-plugin-gcp

Concord collector for Google Cloud Platform. Built on plugin SDK v2.

## Evidence types

| Type | Surface |
|---|---|
| `gcp_iam_policy_bindings` | IAM allow-policy bindings on a project (or folder) |
| `gcp_storage_bucket_iam` | Per-bucket public-access state |
| `gcp_kms_key_rotation` | KMS key rotation policy + last rotation time |
| `gcp_log_sink` | Project-level audit-log sinks + destinations |

Each handler emits the canonical resource envelope:

```json
{
  "fetched_at": "2026-06-06T20:00:00Z",
  "project": "my-project",
  "resources": [
    { "full_name": "projects/p/buckets/logs", "compliant": true,  "reason": "", "detail": {...} },
    { "full_name": "projects/p/buckets/x",    "compliant": false, "reason": "public-access prevention not enforced" }
  ]
}
```

`detail` is type-specific (e.g. binding members for IAM, retention seconds for log sinks).

## Install

```sh
git clone https://github.com/concord-dev/concord-plugin-gcp.git
cd concord-plugin-gcp
make install
```

## Auth

Live GCP calls use Application Default Credentials. Set
`GOOGLE_APPLICATION_CREDENTIALS` to a service-account JSON path. The
plugin only ever needs read-only roles
(`roles/iam.securityReviewer`, `roles/storage.legacyBucketReader`,
`roles/cloudkms.viewer`, `roles/logging.viewer`).

For offline development and CI, point `CONCORD_GCP_FIXTURE_DIR` at a
directory of JSON files named after the evidence type
(`gcp_storage_bucket_iam.json`, etc). Each fixture file is the raw
`resources:` array.

## Wire to a control

```sh
concord scaffold control --pack mycorp --id MYCORP-GCS-1 --template gcp-resource
# Then edit controls/mycorp-gcs-1.yaml to set params.project.
```

Or attach manually:

```yaml
spec:
  evidence:
    - id: gcs_buckets
      source: gcp
      type: gcp_storage_bucket_iam
      params:
        project: acme-prod
```

## Live calls vs fixtures

v0.1.0 ships the SDK shape and fixture-driven flows so packs can ship
real fixtures right away. The live GCP SDK wiring lands in v0.2.0 — the
evidence shape is forward-compatible, so controls written against v0.1.0
fixtures keep working without changes.
