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
	"context"

	"github.com/doublemo/linna/internal/logger"
	"github.com/doublemo/linna/internal/metrics"
	_ "github.com/doublemo/nana/api"
)

// 退出程序
var Shutdown = func() {}

// 开启linna服务
func Serve(ctx context.Context, c Configuration) error {
	log, startupLogger := logger.Logger()

	// 指标
	c.Metrics.Node = c.Name
	localMetrics := metrics.NewLocalMetrics(log, startupLogger, nil, c.Metrics)

	// 启动API服务
	apiServer := NewApiServer(c, localMetrics).Serve()

	NewRuntime(ctx, c.Runtime)
	Shutdown = func() {
		localMetrics.Stop(log)
		apiServer.Stop()
	}
	return nil
}
