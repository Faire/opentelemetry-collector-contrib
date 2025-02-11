// Code generated by mdatagen. DO NOT EDIT.

package metadata

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResourceBuilder(t *testing.T) {
	for _, tt := range []string{"default", "all_set", "none_set"} {
		t.Run(tt, func(t *testing.T) {
			cfg := loadResourceAttributesConfig(t, tt)
			rb := NewResourceBuilder(cfg)
			rb.SetCloudAccountID("cloud.account.id-val")
			rb.SetCloudAvailabilityZone("cloud.availability_zone-val")
			rb.SetCloudPlatform("cloud.platform-val")
			rb.SetCloudProvider("cloud.provider-val")
			rb.SetCloudRegion("cloud.region-val")
			rb.SetFaasID("faas.id-val")
			rb.SetFaasInstance("faas.instance-val")
			rb.SetFaasName("faas.name-val")
			rb.SetFaasVersion("faas.version-val")
			rb.SetGcpCloudRunJobExecution("gcp.cloud_run.job.execution-val")
			rb.SetGcpCloudRunJobTaskIndex("gcp.cloud_run.job.task_index-val")
			rb.SetGcpGceInstanceHostname("gcp.gce.instance.hostname-val")
			rb.SetGcpGceInstanceName("gcp.gce.instance.name-val")
			rb.SetGcpGceInstanceGroupManagerName("gcp.gce.instance_group_manager.name-val")
			rb.SetGcpGceInstanceGroupManagerRegion("gcp.gce.instance_group_manager.region-val")
			rb.SetGcpGceInstanceGroupManagerZone("gcp.gce.instance_group_manager.zone-val")
			rb.SetHostID("host.id-val")
			rb.SetHostName("host.name-val")
			rb.SetHostType("host.type-val")
			rb.SetK8sClusterName("k8s.cluster.name-val")

			res := rb.Emit()
			assert.Equal(t, 0, rb.Emit().Attributes().Len()) // Second call should return empty Resource

			switch tt {
			case "default":
				assert.Equal(t, 18, res.Attributes().Len())
			case "all_set":
				assert.Equal(t, 20, res.Attributes().Len())
			case "none_set":
				assert.Equal(t, 0, res.Attributes().Len())
				return
			default:
				assert.Failf(t, "unexpected test case: %s", tt)
			}

			val, ok := res.Attributes().Get("cloud.account.id")
			assert.True(t, ok)
			if ok {
				assert.EqualValues(t, "cloud.account.id-val", val.Str())
			}
			val, ok = res.Attributes().Get("cloud.availability_zone")
			assert.True(t, ok)
			if ok {
				assert.EqualValues(t, "cloud.availability_zone-val", val.Str())
			}
			val, ok = res.Attributes().Get("cloud.platform")
			assert.True(t, ok)
			if ok {
				assert.EqualValues(t, "cloud.platform-val", val.Str())
			}
			val, ok = res.Attributes().Get("cloud.provider")
			assert.True(t, ok)
			if ok {
				assert.EqualValues(t, "cloud.provider-val", val.Str())
			}
			val, ok = res.Attributes().Get("cloud.region")
			assert.True(t, ok)
			if ok {
				assert.EqualValues(t, "cloud.region-val", val.Str())
			}
			val, ok = res.Attributes().Get("faas.id")
			assert.True(t, ok)
			if ok {
				assert.EqualValues(t, "faas.id-val", val.Str())
			}
			val, ok = res.Attributes().Get("faas.instance")
			assert.True(t, ok)
			if ok {
				assert.EqualValues(t, "faas.instance-val", val.Str())
			}
			val, ok = res.Attributes().Get("faas.name")
			assert.True(t, ok)
			if ok {
				assert.EqualValues(t, "faas.name-val", val.Str())
			}
			val, ok = res.Attributes().Get("faas.version")
			assert.True(t, ok)
			if ok {
				assert.EqualValues(t, "faas.version-val", val.Str())
			}
			val, ok = res.Attributes().Get("gcp.cloud_run.job.execution")
			assert.True(t, ok)
			if ok {
				assert.EqualValues(t, "gcp.cloud_run.job.execution-val", val.Str())
			}
			val, ok = res.Attributes().Get("gcp.cloud_run.job.task_index")
			assert.True(t, ok)
			if ok {
				assert.EqualValues(t, "gcp.cloud_run.job.task_index-val", val.Str())
			}
			val, ok = res.Attributes().Get("gcp.gce.instance.hostname")
			assert.Equal(t, tt == "all_set", ok)
			if ok {
				assert.EqualValues(t, "gcp.gce.instance.hostname-val", val.Str())
			}
			val, ok = res.Attributes().Get("gcp.gce.instance.name")
			assert.Equal(t, tt == "all_set", ok)
			if ok {
				assert.EqualValues(t, "gcp.gce.instance.name-val", val.Str())
			}
			val, ok = res.Attributes().Get("gcp.gce.instance_group_manager.name")
			assert.True(t, ok)
			if ok {
				assert.EqualValues(t, "gcp.gce.instance_group_manager.name-val", val.Str())
			}
			val, ok = res.Attributes().Get("gcp.gce.instance_group_manager.region")
			assert.True(t, ok)
			if ok {
				assert.EqualValues(t, "gcp.gce.instance_group_manager.region-val", val.Str())
			}
			val, ok = res.Attributes().Get("gcp.gce.instance_group_manager.zone")
			assert.True(t, ok)
			if ok {
				assert.EqualValues(t, "gcp.gce.instance_group_manager.zone-val", val.Str())
			}
			val, ok = res.Attributes().Get("host.id")
			assert.True(t, ok)
			if ok {
				assert.EqualValues(t, "host.id-val", val.Str())
			}
			val, ok = res.Attributes().Get("host.name")
			assert.True(t, ok)
			if ok {
				assert.EqualValues(t, "host.name-val", val.Str())
			}
			val, ok = res.Attributes().Get("host.type")
			assert.True(t, ok)
			if ok {
				assert.EqualValues(t, "host.type-val", val.Str())
			}
			val, ok = res.Attributes().Get("k8s.cluster.name")
			assert.True(t, ok)
			if ok {
				assert.EqualValues(t, "k8s.cluster.name-val", val.Str())
			}
		})
	}
}
