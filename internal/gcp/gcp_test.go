package gcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
	"github.com/concord-dev/concord-plugin-sdk/plugin/plugintest"
)

func TestCapabilities_AdvertisesEveryHandler(t *testing.T) {
	caps := plugin.NewSimpleAdapter(Collector{}).Capabilities()
	assert.Equal(t, "gcp", caps.Source)
	assert.Contains(t, caps.SupportedTypes, typeIAMBindings)
	assert.Contains(t, caps.SupportedTypes, typeStorageIAM)
	assert.Contains(t, caps.SupportedTypes, typeKMSRotation)
	assert.Contains(t, caps.SupportedTypes, typeLogSink)
}

func TestHandlers_RequireProjectParam(t *testing.T) {
	c := Collector{}
	for _, h := range c.Handlers() {
		_, err := h.Handle(context.Background(), plugin.EvidenceRef{Type: h.Type})
		require.Error(t, err, "%s without params should error", h.Type)
	}
}

func TestFixtureMode_ReturnsResourcesEnvelope(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "gcp_storage_bucket_iam.json"), []byte(`[
	  {"full_name":"projects/p1/buckets/logs","compliant":true,"reason":"","detail":{"public_access_prevention":"enforced"}},
	  {"full_name":"projects/p1/buckets/public","compliant":false,"reason":"public-access prevention not enforced"}
	]`), 0o644))

	t.Setenv("CONCORD_GCP_FIXTURE_DIR", dir)
	cases := []plugintest.Case{
		{
			Name: "storage-iam-from-fixture",
			Ref: plugin.EvidenceRef{
				Type:   typeStorageIAM,
				Params: map[string]any{"project": "p1"},
			},
		},
	}
	plugintest.Run(t, Collector{}, cases)

	out, err := Collector{}.Handlers()[1].Handle(context.Background(), plugin.EvidenceRef{
		Type:   typeStorageIAM,
		Params: map[string]any{"project": "p1"},
	})
	require.NoError(t, err)
	m := out.(map[string]any)
	assert.Equal(t, "p1", m["project"])
	res := m["resources"].([]resource)
	assert.Len(t, res, 2)
	assert.False(t, res[1].Compliant)
}

func TestProbe_PassesWithFixtureDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CONCORD_GCP_FIXTURE_DIR", dir)
	plugintest.Probe(t, Collector{}, nil)
}

func TestProbe_FailsWithoutCredentials(t *testing.T) {
	t.Setenv("CONCORD_GCP_FIXTURE_DIR", "")
	t.Setenv(envCredentials, "")
	err := Collector{}.Probe(context.Background())
	require.Error(t, err)
}

func TestClassifySink_FlagsNonAuditFilters(t *testing.T) {
	c, _, captures := classifySink("bigquery.googleapis.com/projects/p/datasets/d", "")
	assert.True(t, c)
	assert.True(t, captures)

	c, _, captures = classifySink("bigquery.googleapis.com/projects/p/datasets/d", `logName="projects/p/logs/cloudaudit.googleapis.com%2Factivity"`)
	assert.True(t, c)
	assert.True(t, captures)

	c, _, captures = classifySink("bigquery.googleapis.com/projects/p/datasets/d", `severity>=ERROR AND resource.type=k8s_cluster`)
	assert.True(t, c)
	assert.False(t, captures)

	c, reason, _ := classifySink("", "")
	assert.False(t, c)
	assert.Contains(t, reason, "destination")
}

func TestClassifyBinding_FlagsPublicAndPrimitive(t *testing.T) {
	c, _ := classifyBinding("roles/storage.viewer", []string{"user:alice@example.com"})
	assert.True(t, c)

	c, r := classifyBinding("roles/storage.viewer", []string{"allUsers"})
	assert.False(t, c)
	assert.Contains(t, r, "public")

	c, r = classifyBinding("roles/owner", []string{"user:admin@example.com"})
	assert.False(t, c)
	assert.Contains(t, r, "primitive")
}

func TestLoadFixture_FailsOnMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "gcp_storage_bucket_iam.json"), []byte("{not json"), 0o644))
	t.Setenv("CONCORD_GCP_FIXTURE_DIR", dir)
	_, err := Collector{}.Handlers()[1].Handle(context.Background(), plugin.EvidenceRef{
		Type:   typeStorageIAM,
		Params: map[string]any{"project": "p1"},
	})
	require.Error(t, err)
}
