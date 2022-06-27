// Copyright (c) 2022 The Linna Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package linna

import (
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

// 运行时配置
type RuntimeConfiguration struct {
	Environment map[string]string `yaml:"-" json:"-"`
	Env         []string          `yaml:"env" json:"env" usage:"Values to pass into Runtime as environment variables."`
	Path        string            `yaml:"path" json:"path" usage:"Path for the server to scan for Go library files."`
	HTTPKey     string            `yaml:"http_key" json:"http_key" usage:"Runtime HTTP Invocation key."`
}

func (c *RuntimeConfiguration) Check(log *zap.Logger) error {
	if c.Path == "" {
		c.Path = filepath.Join("./", "data", "modules")
	}

	c.Environment = make(map[string]string, 0)
	for _, e := range c.Env {
		if !strings.Contains(e, "=") {
			log.Fatal("Invalid runtime environment value.", zap.String("value", e))
		}

		kv := strings.SplitN(e, "=", 2)
		if len(kv) == 1 {
			c.Environment[kv[0]] = ""
		} else if len(kv) == 2 {
			c.Environment[kv[0]] = kv[1]
		}
	}
	return nil
}

func NewRuntimeConfiguration() RuntimeConfiguration {
	return RuntimeConfiguration{
		Environment: make(map[string]string, 0),
		Env:         make([]string, 0),
		Path:        "./data/modules",
		HTTPKey:     "defaulthttpkey",
	}
}
