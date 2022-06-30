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

	"github.com/doublemo/linna/cores/cluster"
	"github.com/doublemo/linna/internal/logger"
	"github.com/doublemo/linna/internal/metrics"
	"go.uber.org/zap"
)

// 退出程序
var Shutdown = func() {}

// 开启linna服务
func Serve(ctx context.Context, c Configuration) error {
	log, startupLogger := logger.Logger()

	// 指标
	c.Metrics.Node = c.Name
	localMetrics := metrics.NewLocalMetrics(log, startupLogger, nil, c.Metrics)

	// 启动集群
	clusters, err := cluster.New(ctx, startupLogger, cluster.NewNode(c.Name, cluster.ProtocolHTTP, c.Api.Domain), c.Cluster)
	if err != nil {
		log.Panic("cluster", zap.Error(err))
	}

	r, err := NewRuntime(ctx, startupLogger, c)
	if err != nil {
		log.Panic("runtime", zap.Error(err))
	}
	// 启动API服务
	apiServer := NewApiServer(startupLogger, c, localMetrics, r).Serve()

	Shutdown = func() {
		clusters.Shutdown()
		localMetrics.Stop(log)
		apiServer.Stop()
	}
	return nil
}
