// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0 language governing permissions and
// limitations under the License.

package datadogreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/datadogreceiver"

import (
	"time"

	"go.opentelemetry.io/collector/config/confighttp"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/datadogreceiver/config"
)

func NewConfig() *Config {
	return &Config{
		ServerConfig: confighttp.ServerConfig{
			Endpoint: "localhost:8126",
		},
		ReadTimeout: 60 * time.Second,
		Traces: config.TracesConfig{
			Obfuscation: config.ObfuscationConfig{},
		},
	}
}

type Config struct {
	confighttp.ServerConfig `mapstructure:",squash"`
	// ReadTimeout of the http server
	ReadTimeout time.Duration `mapstructure:"read_timeout"`

	// Traces holds tracing-related configurations
	Traces config.TracesConfig `mapstructure:"traces"`
}
