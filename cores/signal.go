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
// Date: 2022-05-11 18:13:45
// LastEditors: randyma 435420057@qq.com
// LastEditTime: 2022-05-11 18:13:53
// FilePath: \linna\cores\signal.go
// Description: 系统信息处理

//go:build !windows
// +build !windows

package cores

import (
	"os"
	"os/signal"
	"syscall"
)

func NewSignal(ctx context.Context, handle func(command)) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGHUP)
	go func() {
		for {
			select {
			case sig := <-c:
				handle(sig)
			case <-ctx.Done():
				
			}
		}
	}()
}
