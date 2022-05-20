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
	"os"
	"path/filepath"

	"github.com/doublemo/linna/internal/endpoint"
	"github.com/doublemo/linna/internal/logger"
	"github.com/doublemo/linna/internal/metrics"
	"go.uber.org/zap"
)

// Configuration 配置
type Configuration struct {
	SourceFile string                 `yaml:"-" json:"config" usage:"配置文件地址"`
	Datadir    string                 `yaml:"data_dir" json:"data_dir" usage:"指向可写文件夹的绝对路径，Linna将在其中存储其数据."`
	Endpoint   endpoint.Configuration `yaml:"endpoint" json:"endpoint" usage:"节点信息"`
	Logger     logger.Configuration   `yaml:"log" json:"log" usage:"日志信息配置"`
	Runtime    RuntimeConfiguration   `yaml:"runtime" json:"runtime" usage:"运行时"`
	Metrics    metrics.Configuration  `yaml:"metrics" json:"metrics" usage:"指标信息"`
}

func (c Configuration) Check() error {
	return nil
}

func NewConfiguration() Configuration {
	log := logger.StartupLogger()
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal("Error getting current working directory.", zap.Error(err))
	}

	return Configuration{
		SourceFile: "./config.yml",
		Datadir:    filepath.Join(cwd, "data"),
		Endpoint:   endpoint.NewConfiguration(),
		Logger:     logger.NewConfiguration(),
		Runtime:    NewRuntimeConfiguration(),
	}
}
