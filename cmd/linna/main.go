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
// Date: 2022-05-11 15:36:25
// LastEditors: randyma 435420057@qq.com
// LastEditTime: 2022-05-11 15:36:33
// FilePath: \linna\cmd\linna\main.go
// Description:

package main

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/doublemo/linna/cores"
	"github.com/doublemo/linna/internal/logger"
	"github.com/doublemo/linna/kits/linna"
	"go.uber.org/zap"
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

	// 随机种子
	var seed int64
	if err := binary.Read(crand.Reader, binary.BigEndian, &seed); err != nil {
		startupLogger.Warn("failed to get strongly random seed, fallback to a less random one.", zap.Error(err))
		seed = time.Now().UnixNano()
	}
	rand.Seed(seed)

	// 启动主程序
	if err := linna.Serve(config); err != nil {
		log.Panic(err.Error())
	}

	// 系统信号处理
	ctx, cancel := context.WithCancel(context.Background())
	cores.Signal(ctx, func(sig cores.SignalCommand) {
		switch sig {
		case cores.SignalINT, cores.SignalTERM:
			linna.Shutdown()
			cancel()

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
