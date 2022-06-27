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
//
// Author: randyma
// Date: 2022-05-12 09:58:12
// LastEditors: randyma
// LastEditTime: 2022-05-12 10:40:21
// Description: Linna配置定义

package linna

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/doublemo/linna/internal/logger"
	"github.com/doublemo/linna/internal/metrics"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

// Configuration 配置
type Configuration struct {
	Name        string                `yaml:"name" json:"name" usage:"Linna server’s node name - must be unique."`
	Config      []string              `yaml:"config" json:"config" usage:"The absolute file path to configuration YAML file."`
	Datadir     string                `yaml:"data_dir" json:"data_dir" usage:"An absolute path to a writeable folder where Linna will store its data."`
	Logger      logger.Configuration  `yaml:"log" json:"log" usage:"Logger levels and output."`
	Api         ApiConfiguration      `yaml:"api" json:"api" usage:"api server."`
	Metrics     metrics.Configuration `yaml:"metrics" json:"metrics" usage:"Metrics settings."`
	Runtime     RuntimeConfiguration  `yaml:"runtime" json:"runtime" usage:"runtime settings."`
	CurrentPath string
	log         *zap.Logger
}

func (c *Configuration) Check(log *zap.Logger) error {
	if err := c.Api.Check(log); err != nil {
		return err
	}

	if err := c.Runtime.Check(log); err != nil {
		return err
	}

	return nil
}

func (c *Configuration) Parse() error {
	for _, path := range c.Config {
		f, err := os.Stat(path)
		if os.IsNotExist(err) {
			return err
		}

		if !f.IsDir() {
			return c.parseYml(path)
		}

		matches, err := filepath.Glob(filepath.Join(path, "*.yml"))
		if err != nil {
			return err
		}

		for _, cfg := range matches {
			if err := c.parseYml(cfg); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Configuration) parseYml(cfg string) error {
	data, err := ioutil.ReadFile(cfg)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(data, c)
	if err != nil {
		return err
	}
	c.log.Info("Successfully loaded config file", zap.String("path", cfg))
	return nil
}

func NewConfiguration(log *zap.Logger) *Configuration {
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal("Error getting current working directory.", zap.Error(err))
	}

	return &Configuration{
		Name:        "linna",
		Datadir:     filepath.Join(cwd, "data"),
		Logger:      logger.NewConfiguration(),
		Api:         NewApiConfiguration(),
		Metrics:     metrics.NewConfiguration(),
		Runtime:     NewRuntimeConfiguration(),
		CurrentPath: cwd,
		log:         log,
	}
}
