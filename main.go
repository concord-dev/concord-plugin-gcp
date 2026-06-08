// concord-plugin-gcp emits GCP IAM, GCS, KMS, and audit-log evidence for Concord.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"cloud.google.com/go/logging/logadmin"
	"cloud.google.com/go/storage"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/durationpb"

	plugin "github.com/concord-dev/concord/pkg/plugin"
	"github.com/concord-dev/concord/pkg/plugin/evidence"
)

const (
	source  = "gcp"
	version = "v0.2.0"

	typeIAMBindings = "gcp_iam_policy_bindings"
	typeStorageIAM  = "gcp_storage_bucket_iam"
	typeKMSRotation = "gcp_kms_key_rotation"
	typeLogSink     = "gcp_log_sink"

	envCredentials = "GOOGLE_APPLICATION_CREDENTIALS"
	envFixture     = "CONCORD_GCP_FIXTURE_DIR"

	defaultMaxRotationDays = 90
)

var primitiveRoles = map[string]bool{
	"roles/owner":  true,
	"roles/editor": true,
	"roles/viewer": true,
}

var publicMembers = map[string]bool{
	"allUsers":              true,
	"allAuthenticatedUsers": true,
}

type gcpCollector struct{}

func (gcpCollector) Source() string  { return source }
func (gcpCollector) Version() string { return version }

func (gcpCollector) Probe(ctx context.Context) error {
	if os.Getenv(envFixture) != "" {
		return nil
	}
	if os.Getenv(envCredentials) == "" {
		return fmt.Errorf("set %s to a service-account JSON path (or %s for offline mode)", envCredentials, envFixture)
	}
	svc, err := cloudresourcemanager.NewService(ctx, option.WithScopes(cloudresourcemanager.CloudPlatformReadOnlyScope))
	if err != nil {
		return fmt.Errorf("gcp: probe failed: %w", err)
	}
	if _, err := svc.Projects.Search().PageSize(1).Context(ctx).Do(); err != nil {
		return fmt.Errorf("gcp: probe failed: %w", err)
	}
	return nil
}

func (gcpCollector) Handlers() []plugin.TypeHandler {
	return []plugin.TypeHandler{
		{Type: typeIAMBindings, Description: "IAM allow-policy bindings for a project; flags public + primitive-role grants", Handle: handleIAMBindings},
		{Type: typeStorageIAM, Description: "GCS bucket IAM + PublicAccessPrevention + UBLA", Handle: handleStorageIAM},
		{Type: typeKMSRotation, Description: "KMS CryptoKey rotation policy + next-rotation time", Handle: handleKMSRotation},
		{Type: typeLogSink, Description: "Cloud Logging sinks for the project", Handle: handleLogSink},
	}
}

func handleIAMBindings(ctx context.Context, ref plugin.EvidenceRef) (any, error) {
	project, err := evidence.Required(ref.Params, "project")
	if err != nil {
		return nil, err
	}
	if items, ok := loadFixture(ref); ok {
		return wrap(items, project), nil
	}
	svc, err := cloudresourcemanager.NewService(ctx, option.WithScopes(cloudresourcemanager.CloudPlatformReadOnlyScope))
	if err != nil {
		return nil, fmt.Errorf("gcp: resourcemanager.NewService: %w", err)
	}
	policy, err := svc.Projects.GetIamPolicy("projects/"+project, &cloudresourcemanager.GetIamPolicyRequest{
		Options: &cloudresourcemanager.GetPolicyOptions{RequestedPolicyVersion: 3},
	}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("gcp: projects.GetIamPolicy: %w", err)
	}
	out := make([]resource, 0, len(policy.Bindings))
	for _, b := range policy.Bindings {
		compliant, reason := classifyBinding(b.Role, b.Members)
		members := append([]string(nil), b.Members...)
		sort.Strings(members)
		out = append(out, resource{
			FullName:  fmt.Sprintf("projects/%s/iam/%s", project, b.Role),
			Compliant: compliant,
			Reason:    reason,
			Detail: map[string]any{
				"role":    b.Role,
				"members": members,
			},
		})
	}
	return wrap(out, project), nil
}

func classifyBinding(role string, members []string) (bool, string) {
	for _, m := range members {
		bare := strings.TrimPrefix(m, "user:")
		bare = strings.TrimPrefix(bare, "group:")
		bare = strings.TrimPrefix(bare, "serviceAccount:")
		if publicMembers[m] || publicMembers[bare] {
			return false, fmt.Sprintf("role %s granted to public principal %s", role, m)
		}
	}
	if primitiveRoles[role] && role != "roles/viewer" {
		return false, fmt.Sprintf("primitive role %s in use; prefer least-privilege predefined roles", role)
	}
	return true, ""
}

func handleStorageIAM(ctx context.Context, ref plugin.EvidenceRef) (any, error) {
	project, err := evidence.Required(ref.Params, "project")
	if err != nil {
		return nil, err
	}
	if items, ok := loadFixture(ref); ok {
		return wrap(items, project), nil
	}
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp: storage.NewClient: %w", err)
	}
	defer client.Close()

	out := []resource{}
	it := client.Buckets(ctx, project)
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("gcp: buckets.list: %w", err)
		}
		policy, perr := client.Bucket(attrs.Name).IAM().V3().Policy(ctx)
		var members []string
		if perr == nil {
			seen := map[string]bool{}
			for _, b := range policy.Bindings {
				for _, m := range b.Members {
					if !seen[m] {
						members = append(members, m)
						seen[m] = true
					}
				}
			}
			sort.Strings(members)
		}
		compliant, reason := classifyBucket(attrs, members)
		out = append(out, resource{
			FullName:  fmt.Sprintf("projects/%s/buckets/%s", project, attrs.Name),
			Compliant: compliant,
			Reason:    reason,
			Detail: map[string]any{
				"public_access_prevention":    publicAccessPreventionString(attrs.PublicAccessPrevention),
				"uniform_bucket_level_access": attrs.UniformBucketLevelAccess.Enabled,
				"location":                    attrs.Location,
				"members":                     members,
			},
		})
		if len(out) > 5000 {
			break
		}
	}
	return wrap(out, project), nil
}

func classifyBucket(attrs *storage.BucketAttrs, members []string) (bool, string) {
	for _, m := range members {
		if publicMembers[m] || publicMembers[strings.TrimPrefix(m, "user:")] {
			return false, fmt.Sprintf("bucket grants access to public principal %s", m)
		}
	}
	if attrs.PublicAccessPrevention != storage.PublicAccessPreventionEnforced {
		return false, "public-access prevention is not enforced"
	}
	if !attrs.UniformBucketLevelAccess.Enabled {
		return false, "uniform bucket-level access is not enabled"
	}
	return true, ""
}

func handleKMSRotation(ctx context.Context, ref plugin.EvidenceRef) (any, error) {
	project, err := evidence.Required(ref.Params, "project")
	if err != nil {
		return nil, err
	}
	if items, ok := loadFixture(ref); ok {
		return wrap(items, project), nil
	}
	maxRotation := time.Duration(evidence.Int(ref.Params, "max_rotation_days", defaultMaxRotationDays)) * 24 * time.Hour
	locations := stringSliceParam(ref.Params, "locations", []string{"global"})

	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp: kms.NewKeyManagementClient: %w", err)
	}
	defer client.Close()

	out := []resource{}
	for _, loc := range locations {
		ringIt := client.ListKeyRings(ctx, &kmspb.ListKeyRingsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", project, loc),
		})
		for {
			ring, err := ringIt.Next()
			if errors.Is(err, iterator.Done) {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("gcp: kms.ListKeyRings(%s): %w", loc, err)
			}
			keyIt := client.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{Parent: ring.Name})
			for {
				key, err := keyIt.Next()
				if errors.Is(err, iterator.Done) {
					break
				}
				if err != nil {
					return nil, fmt.Errorf("gcp: kms.ListCryptoKeys: %w", err)
				}
				compliant, reason := classifyCryptoKey(key, maxRotation)
				out = append(out, resource{
					FullName:  key.Name,
					Compliant: compliant,
					Reason:    reason,
					Detail: map[string]any{
						"rotation_period_seconds": rotationSeconds(key.GetRotationPeriod()),
						"next_rotation_time":      timestampString(key.GetNextRotationTime().AsTime()),
						"purpose":                 key.Purpose.String(),
					},
				})
				if len(out) > 5000 {
					break
				}
			}
		}
	}
	return wrap(out, project), nil
}

func classifyCryptoKey(key *kmspb.CryptoKey, maxRotation time.Duration) (bool, string) {
	if key.Purpose != kmspb.CryptoKey_ENCRYPT_DECRYPT {
		return true, ""
	}
	period := key.GetRotationPeriod()
	if period == nil {
		return false, "rotation policy not configured"
	}
	dur := period.AsDuration()
	if dur > maxRotation {
		return false, fmt.Sprintf("rotation period %s exceeds policy of %s", dur, maxRotation)
	}
	next := key.GetNextRotationTime()
	if next == nil {
		return false, "next-rotation time not set"
	}
	if next.AsTime().Before(time.Now().Add(-24 * time.Hour)) {
		return false, "rotation overdue (next_rotation_time in the past)"
	}
	return true, ""
}

func handleLogSink(ctx context.Context, ref plugin.EvidenceRef) (any, error) {
	project, err := evidence.Required(ref.Params, "project")
	if err != nil {
		return nil, err
	}
	if items, ok := loadFixture(ref); ok {
		return wrap(items, project), nil
	}
	client, err := logadmin.NewClient(ctx, project)
	if err != nil {
		return nil, fmt.Errorf("gcp: logadmin.NewClient: %w", err)
	}
	defer client.Close()

	out := []resource{}
	it := client.Sinks(ctx)
	for {
		s, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("gcp: sinks.list: %w", err)
		}
		compliant, reason := classifySink(s.Destination, s.Filter)
		out = append(out, resource{
			FullName:  fmt.Sprintf("projects/%s/sinks/%s", project, s.ID),
			Compliant: compliant,
			Reason:    reason,
			Detail: map[string]any{
				"destination": s.Destination,
				"filter":      s.Filter,
			},
		})
		if len(out) > 5000 {
			break
		}
	}
	if len(out) == 0 {
		out = append(out, resource{
			FullName:  fmt.Sprintf("projects/%s/sinks", project),
			Compliant: false,
			Reason:    "no log sinks configured",
		})
	}
	return wrap(out, project), nil
}

func classifySink(destination, filter string) (bool, string) {
	if destination == "" {
		return false, "sink destination is empty"
	}
	if filter == "" {
		return true, ""
	}
	return true, ""
}

func publicAccessPreventionString(p storage.PublicAccessPrevention) string {
	switch p {
	case storage.PublicAccessPreventionEnforced:
		return "enforced"
	case storage.PublicAccessPreventionInherited:
		return "inherited"
	case storage.PublicAccessPreventionUnknown:
		return "unknown"
	}
	return "unspecified"
}

func rotationSeconds(d *durationpb.Duration) int64 {
	if d == nil {
		return 0
	}
	return int64(d.AsDuration().Seconds())
}

func timestampString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func stringSliceParam(params map[string]any, key string, dflt []string) []string {
	v, ok := params[key]
	if !ok {
		return dflt
	}
	switch x := v.(type) {
	case []string:
		if len(x) == 0 {
			return dflt
		}
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return dflt
		}
		return out
	case string:
		if x == "" {
			return dflt
		}
		return []string{x}
	}
	return dflt
}

type resource struct {
	FullName  string         `json:"full_name"`
	Compliant bool           `json:"compliant"`
	Reason    string         `json:"reason,omitempty"`
	Detail    map[string]any `json:"detail,omitempty"`
}

func wrap(items []resource, project string) map[string]any {
	if items == nil {
		items = []resource{}
	}
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"project":    project,
		"resources":  items,
	}
}

func loadFixture(ref plugin.EvidenceRef) ([]resource, bool) {
	path := evidence.String(ref.Params, "fixture")
	if path == "" {
		root := os.Getenv(envFixture)
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
		plugin.WithOptionalEnv(envCredentials, envFixture),
		plugin.WithPermissions(plugin.Permissions{Network: []string{
			"cloudresourcemanager.googleapis.com",
			"storage.googleapis.com",
			"cloudkms.googleapis.com",
			"logging.googleapis.com",
			"oauth2.googleapis.com",
		}}),
	)
}
