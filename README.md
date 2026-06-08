# concord-plugin-gcp

Concord collector for Google Cloud Platform. v0.2.0 uses **real
`cloud.google.com/go` SDKs** + `google.golang.org/api`; fixture mode is
kept as the offline / CI fallback.

## Evidence types

| Type | What it actually does in live mode |
|---|---|
| `gcp_iam_policy_bindings` | `projects.GetIamPolicy` (Resource Manager v3). Flags bindings granted to `allUsers` / `allAuthenticatedUsers`, and primitive roles (`roles/owner`, `roles/editor`). |
| `gcp_storage_bucket_iam` | `storage.Buckets.list` then `bucket.IAM().V3().Policy` per bucket. Flags buckets where `PublicAccessPrevention != enforced`, UBLA is off, or IAM grants `allUsers` / `allAuthenticatedUsers`. |
| `gcp_kms_key_rotation` | `kms.ListKeyRings` × `kms.ListCryptoKeys` across `params.locations` (default `["global"]`). Flags `ENCRYPT_DECRYPT` keys with rotation > `params.max_rotation_days` (default 90), missing rotation policy, or overdue rotation. |
| `gcp_log_sink` | `logadmin.Sinks` — flags the absence of any sink for the project. |

Each handler emits the canonical resource envelope:

```json
{
  "fetched_at": "2026-06-08T20:00:00Z",
  "project": "my-project",
  "resources": [
    { "full_name": "projects/p/buckets/logs", "compliant": true,  "detail": {...} },
    { "full_name": "projects/p/buckets/x",    "compliant": false, "reason": "public-access prevention is not enforced" }
  ]
}
```

## Auth

| Env var | Required | Notes |
|---|---|---|
| `GOOGLE_APPLICATION_CREDENTIALS` | live mode | Service-account JSON path. Read-only roles suffice: `roles/iam.securityReviewer`, `roles/storage.legacyBucketReader`, `roles/cloudkms.viewer`, `roles/logging.viewer`. |
| `CONCORD_GCP_FIXTURE_DIR` | offline / CI | When set, reads `<type>.json` from this directory |

`Probe()` calls `Projects.Search` with page size 1 so misconfigured ADC
fails at plugin start, not at first collection.

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

## Status

- v0.1.0 — fixture mode only (stub release; do not use in production)
- v0.2.0 — **real cloud.google.com/go SDK**, IAM + GCS + KMS + Log Sinks ← current
