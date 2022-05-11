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
// Author: randyma 435420057@qq.com
// Date: 2022-05-11 18:01:10
// LastEditors: randyma 435420057@qq.com
// LastEditTime: 2022-05-11 18:01:15
// FilePath: \linna\internal\metrics\metrics.go
// Description: 日志收集

package metrics

// Configuration 日志配置信息
type Configuration struct {
	ReportingFreqSec int    `yaml:"reporting_freq_sec" json:"reporting_freq_sec" usage:"Frequency of metrics exports. Default is 60 seconds."`
	Namespace        string `yaml:"namespace" json:"namespace" usage:"Namespace for Prometheus metrics. It will always prepend node name."`
	PrometheusPort   int    `yaml:"prometheus_port" json:"prometheus_port" usage:"Port to expose Prometheus. If '0' Prometheus exports are disabled."`
	Prefix           string `yaml:"prefix" json:"prefix" usage:"Prefix for metric names. Default is 'nakama', empty string '' disables the prefix."`
	CustomPrefix     string `yaml:"custom_prefix" json:"custom_prefix" usage:"Prefix for custom runtime metric names. Default is 'custom', empty string '' disables the prefix."`
}
