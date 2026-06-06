// concord-plugin-gcp emits GCP IAM, GCS, KMS, and audit-log evidence for Concord.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	plugin "github.com/concord-dev/concord/pkg/plugin"
	"github.com/concord-dev/concord/pkg/plugin/evidence"
)

const (
	source  = "gcp"
	version = "v0.1.0"

	typeIAMBindings  = "gcp_iam_policy_bindings"
	typeStorageIAM   = "gcp_storage_bucket_iam"
	typeKMSRotation  = "gcp_kms_key_rotation"
	typeLogSink      = "gcp_log_sink"

	envCredentials = "GOOGLE_APPLICATION_CREDENTIALS"
)

type gcpCollector struct{}

func (gcpCollector) Source() string  { return source }
func (gcpCollector) Version() string { return version }

func (gcpCollector) Probe(_ context.Context) error {
	if os.Getenv("CONCORD_GCP_FIXTURE_DIR") != "" {
		return nil
	}
	if os.Getenv(envCredentials) == "" {
		return fmt.Errorf("set %s to a service-account JSON path (or CONCORD_GCP_FIXTURE_DIR for offline mode)", envCredentials)
	}
	return nil
}

func (gcpCollector) Handlers() []plugin.TypeHandler {
	return []plugin.TypeHandler{
		{Type: typeIAMBindings, Description: "IAM allow-policy bindings for a project or folder", Handle: handleIAMBindings},
		{Type: typeStorageIAM, Description: "Public-access state for every GCS bucket in a project", Handle: handleStorageIAM},
		{Type: typeKMSRotation, Description: "KMS key rotation policy + last rotation time", Handle: handleKMSRotation},
		{Type: typeLogSink, Description: "Sink configuration for project-level audit logs", Handle: handleLogSink},
	}
}

func handleIAMBindings(_ context.Context, ref plugin.EvidenceRef) (any, error) {
	project, err := evidence.Required(ref.Params, "project")
	if err != nil {
		return nil, err
	}
	if items, ok := loadFixture(ref); ok {
		return wrapResources(items, project)
	}
	return nil, errors.New("gcp: live IAM client not yet wired; supply params.fixture or CONCORD_GCP_FIXTURE_DIR")
}

func handleStorageIAM(_ context.Context, ref plugin.EvidenceRef) (any, error) {
	project, err := evidence.Required(ref.Params, "project")
	if err != nil {
		return nil, err
	}
	if items, ok := loadFixture(ref); ok {
		return wrapResources(items, project)
	}
	return nil, errors.New("gcp: live GCS client not yet wired; supply params.fixture or CONCORD_GCP_FIXTURE_DIR")
}

func handleKMSRotation(_ context.Context, ref plugin.EvidenceRef) (any, error) {
	project, err := evidence.Required(ref.Params, "project")
	if err != nil {
		return nil, err
	}
	if items, ok := loadFixture(ref); ok {
		return wrapResources(items, project)
	}
	return nil, errors.New("gcp: live KMS client not yet wired; supply params.fixture or CONCORD_GCP_FIXTURE_DIR")
}

func handleLogSink(_ context.Context, ref plugin.EvidenceRef) (any, error) {
	project, err := evidence.Required(ref.Params, "project")
	if err != nil {
		return nil, err
	}
	if items, ok := loadFixture(ref); ok {
		return wrapResources(items, project)
	}
	return nil, errors.New("gcp: live Logging client not yet wired; supply params.fixture or CONCORD_GCP_FIXTURE_DIR")
}

type resource struct {
	FullName  string         `json:"full_name"`
	Compliant bool           `json:"compliant"`
	Reason    string         `json:"reason,omitempty"`
	Detail    map[string]any `json:"detail,omitempty"`
}

func wrapResources(items []resource, project string) (any, error) {
	if items == nil {
		items = []resource{}
	}
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"project":    project,
		"resources":  items,
	}, nil
}

func loadFixture(ref plugin.EvidenceRef) ([]resource, bool) {
	path := evidence.String(ref.Params, "fixture")
	if path == "" {
		root := os.Getenv("CONCORD_GCP_FIXTURE_DIR")
		if root == "" {
			return nil, false
		}
		path = root + "/" + ref.Type + ".json"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var items []resource
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, false
	}
	return items, true
}

func main() {
	plugin.ServeSimple(gcpCollector{},
		plugin.WithDocs("https://github.com/concord-dev/concord-plugin-gcp"),
		plugin.WithOptionalEnv(envCredentials, "CONCORD_GCP_FIXTURE_DIR"),
		plugin.WithPermissions(plugin.Permissions{Network: []string{"googleapis.com"}}),
	)
}
