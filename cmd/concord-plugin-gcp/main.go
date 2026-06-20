// Command concord-plugin-gcp emits GCP IAM, GCS, KMS, and audit-log evidence for Concord.
package main

import (
	"github.com/concord-dev/concord-plugin-gcp/internal/gcp"
	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

func main() {
	plugin.ServeSimple(gcp.New(),
		plugin.WithDocs("https://github.com/concord-dev/concord-plugin-gcp"),
		plugin.WithOptionalEnv("GOOGLE_APPLICATION_CREDENTIALS", "CONCORD_GCP_FIXTURE_DIR"),
		plugin.WithPermissions(plugin.Permissions{Network: []string{
			"cloudresourcemanager.googleapis.com",
			"storage.googleapis.com",
			"cloudkms.googleapis.com",
			"logging.googleapis.com",
			"oauth2.googleapis.com",
		}}),
	)
}
