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
// LastEditTime: 2022-05-12 10:39:46
// Description: Linna 主入口文件

package main

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"os"
	"runtime"
	"time"

	"github.com/doublemo/linna/cores"
	"github.com/doublemo/linna/internal/logger"
	"github.com/doublemo/linna/kits/linna"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// 定义版本信息
var (
	// version 版本号
	version string = "0.1.0"

	// commitid 代码提交版本号
	commitid string = "default"

	// builddate 编译日期
	builddate string = "default"
)

func main() {
	// 日志
	log, startupLogger := logger.Logger()

	// 参数解析
	config := linna.ParseArgs(log, version, commitid, builddate)
	if err := config.Check(); err != nil {
		startupLogger.Panic(err.Error())
	}

	// 日志重建
	log, startupLogger = logger.New(log, config.Logger)
	logger.Initializer(log, startupLogger)
	startupLogger.Info("Linna starting")
	programInfo := []zapcore.Field{
		zap.String("id", config.Endpoint.ID),
		zap.String("name", config.Endpoint.Name),
		zap.String("version", version),
		zap.String("runtime", runtime.Version()),
		zap.Int("cpu", runtime.NumCPU()),
		zap.Int("proc", runtime.GOMAXPROCS(0)),
	}
	startupLogger.Info("Node", programInfo...)
	startupLogger.Info("Data directory", zap.String("path", config.Datadir))

	// 随机种子
	var seed int64
	if err := binary.Read(crand.Reader, binary.BigEndian, &seed); err != nil {
		startupLogger.Warn("failed to get strongly random seed, fallback to a less random one.", zap.Error(err))
		seed = time.Now().UnixNano()
	}
	rand.Seed(seed)

	// 系统信号处理
	ctx, ctxCancelFn := context.WithCancel(context.Background())

	// 启动主程序
	if err := linna.Serve(ctx, config); err != nil {
		log.Panic(err.Error())
	}

	cores.Signal(ctx, func(sig cores.SignalCommand) {
		switch sig {
		case cores.SignalINT, cores.SignalTERM:
			ctxCancelFn()
			linna.Shutdown()

		case cores.SignalHUP:
			if err := linna.Reload(config); err != nil {
				startupLogger.Error("Linna 重新加载失败")
				os.Exit(2)
			}
		}
	})

	startupLogger.Info("Linna complete")
	os.Exit(0)
}
