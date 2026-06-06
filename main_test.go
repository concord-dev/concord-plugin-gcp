package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord/pkg/plugin"
	"github.com/concord-dev/concord/pkg/plugin/plugintest"
)

func TestCapabilities_AdvertisesEveryHandler(t *testing.T) {
	caps := plugin.NewSimpleAdapter(gcpCollector{}).Capabilities()
	assert.Equal(t, "gcp", caps.Source)
	assert.Contains(t, caps.SupportedTypes, typeIAMBindings)
	assert.Contains(t, caps.SupportedTypes, typeStorageIAM)
	assert.Contains(t, caps.SupportedTypes, typeKMSRotation)
	assert.Contains(t, caps.SupportedTypes, typeLogSink)
}

func TestHandlers_RequireProjectParam(t *testing.T) {
	c := gcpCollector{}
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
	plugintest.Run(t, gcpCollector{}, cases)

	out, err := gcpCollector{}.Handlers()[1].Handle(context.Background(), plugin.EvidenceRef{
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
	plugintest.Probe(t, gcpCollector{}, nil)
}

func TestProbe_FailsWithoutCredentials(t *testing.T) {
	t.Setenv("CONCORD_GCP_FIXTURE_DIR", "")
	t.Setenv(envCredentials, "")
	err := gcpCollector{}.Probe(context.Background())
	require.Error(t, err)
}
