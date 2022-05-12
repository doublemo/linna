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
// LastEditTime: 2022-05-12 10:35:00
// Description:

//go:build !windows
// +build !windows

package cores

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// Signal 处理系统信号
func Signal(ctx context.Context, handle func(SignalCommand)) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGHUP)
loop:
	for {
		select {
		case sig := <-c:
			switch sig {
			case syscall.SIGINT:
				handle(SignalINT)

			case syscall.SIGTERM:
				handle(SignalTERM)

			case syscall.SIGUSR1:
				handle(SignalUSR1)

			case syscall.SIGUSR2:
				handle(SignalUSR2)

			case syscall.SIGHUP:
				handle(SignalHUP)
			}

			// go
			goto loop

		case <-ctx.Done():
			return
		}
	}
}
