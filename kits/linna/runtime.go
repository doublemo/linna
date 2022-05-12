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
// Date: 2022-05-09 09:37:28
// LastEditors: randyma
// LastEditTime: 2022-05-12 10:41:26
// Description: Nakama运行时实现,代码大部来至nakama,部分代码根据自己的需要修改
// Reference: https://github.com/heroiclabs/nakama

package linna

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/doublemo/linna/internal/logger"
	"go.uber.org/zap"
)

// RuntimeConfiguration 定义运行时配置
type RuntimeConfiguration struct {
	Environment        map[string]string `yaml:"-" json:"-"`
	Env                []string          `yaml:"env" json:"env" usage:"作为环境变量传递到运行时的值"`
	Path               string            `yaml:"path" json:"path" usage:"服务器扫描Lua和Go库文件的路径"`
	HTTPKey            string            `yaml:"http_key" json:"http_key" usage:"运行时HTTP调用密钥"`
	MinCount           int               `yaml:"min_count" json:"min_count" usage:"要分配的Lua运行时实例的最小数量。默认值为0"` // Kept for backwards compatibility
	LuaMinCount        int               `yaml:"lua_min_count" json:"lua_min_count" usage:"要分配的Lua运行时实例的最小数量。默认16"`
	MaxCount           int               `yaml:"max_count" json:"max_count" usage:"要分配的Lua运行时实例的最大数量。默认值为0"` // Kept for backwards compatibility
	LuaMaxCount        int               `yaml:"lua_max_count" json:"lua_max_count" usage:"要分配的Lua运行时实例的最大数量。默认48"`
	JsMinCount         int               `yaml:"js_min_count" json:"js_min_count" usage:"要分配的最小Javascript运行时实例数。默认0."`
	JsMaxCount         int               `yaml:"js_max_count" json:"js_max_count" usage:"要分配的最大Javascript运行时实例数。默认48"`
	CallStackSize      int               `yaml:"call_stack_size" json:"call_stack_size" usage:"每个运行时实例的调用堆栈的大小。默认值为0"` // Kept for backwards compatibility
	LuaCallStackSize   int               `yaml:"lua_call_stack_size" json:"lua_call_stack_size" usage:"每个运行时实例的调用堆栈的大小。默认128"`
	RegistrySize       int               `yaml:"registry_size" json:"registry_size" usage:"每个Lua运行时实例注册表的大小。默认值为0"` // Kept for backwards compatibility
	LuaRegistrySize    int               `yaml:"lua_registry_size" json:"lua_registry_size" usage:"每个Lua运行时实例注册表的大小。默认512"`
	EventQueueSize     int               `yaml:"event_queue_size" json:"event_queue_size" usage:"事件队列缓冲区的大小。默认为65536"`
	EventQueueWorkers  int               `yaml:"event_queue_workers" json:"event_queue_workers" usage:"用于并发处理事件的工作进程数。默认值8"`
	ReadOnlyGlobals    bool              `yaml:"read_only_globals" json:"read_only_globals" usage:"启用时,将所有Lua运行时全局表标记为只读,以减少内存占用。默认为true"` // Kept for backwards compatibility
	LuaReadOnlyGlobals bool              `yaml:"lua_read_only_globals" json:"lua_read_only_globals" usage:"启用时,将所有Lua运行时全局表标记为只读,以减少内存占用。默认为true"`
	JsReadOnlyGlobals  bool              `yaml:"js_read_only_globals" json:"js_read_only_globals" usage:"启用时,将所有Javascript运行时全局标记为只读,以减少内存占用。默认为true"`
	LuaApiStacktrace   bool              `yaml:"lua_api_stacktrace" json:"lua_api_stacktrace" usage:"将Lua stacktrace包含在返回给客户端的错误响应中。默认错误"`
	JsEntrypoint       string            `yaml:"js_entrypoint" json:"js_entrypoint" usage:"指定绑定的JavaScript运行时源代码的位置"`
}

// NewRuntimeConfiguration 创建运行时配置文件
func NewRuntimeConfiguration() RuntimeConfiguration {
	return RuntimeConfiguration{
		Environment:        make(map[string]string, 0),
		Env:                make([]string, 0),
		Path:               "",
		HTTPKey:            "defaulthttpkey",
		LuaMinCount:        16,
		LuaMaxCount:        48,
		LuaCallStackSize:   128,
		LuaRegistrySize:    512,
		JsMinCount:         16,
		JsMaxCount:         32,
		EventQueueSize:     65536,
		EventQueueWorkers:  8,
		ReadOnlyGlobals:    true,
		LuaReadOnlyGlobals: true,
		JsReadOnlyGlobals:  true,
		LuaApiStacktrace:   false,
	}
}

// RuntimeInfo 运行时信息
type RuntimeInfo struct{}

// RuntimeBeforeReqFunctions 运行时调用方法前
type RuntimeBeforeReqFunctions struct{}

// RuntimeAfterReqFunctions运行时调用方法后
type RuntimeAfterReqFunctions struct{}

// Runtime 运行时
type Runtime struct{}

type moduleInfo struct {
	path    string
	modTime time.Time
}

// NewRuntime 创建运行时,支持lua, js , go
func NewRuntime(ctx context.Context, config Configuration) (*Runtime, *RuntimeInfo, error) {
	log, startupLogger := logger.Logger()
	startupLogger.Info("Initialising runtime", zap.String("path", config.Runtime.Path))

	paths, err := GetRuntimePaths(startupLogger, config.Runtime.Path)
	if err != nil {
		return nil, nil, err
	}

	startupLogger.Info("Initialising runtime event queue processor")
	eventQueue := NewRuntimeEventQueue(log, config)
	startupLogger.Info("Runtime event queue processor started", zap.Int("size", config.Runtime.EventQueueSize), zap.Int("workers", config.Runtime.EventQueueWorkers))

	fmt.Println(paths, eventQueue)
	return nil, nil, nil
}

func GetRuntimePaths(logger *zap.Logger, rootPath string) ([]string, error) {
	if err := os.MkdirAll(rootPath, os.ModePerm); err != nil {
		return nil, err
	}

	paths := make([]string, 0, 5)
	if err := filepath.Walk(rootPath, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			logger.Error("Error listing runtime path", zap.String("path", path), zap.Error(err))
			return err
		}

		// Ignore directories.
		if !f.IsDir() {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		logger.Error("Failed to list runtime path", zap.Error(err))
		return nil, err
	}

	return paths, nil
}

func CheckRuntime(logger *zap.Logger, config Configuration) error {
	// Get all paths inside the configured runtime.
	paths, err := GetRuntimePaths(logger, config.Runtime.Path)
	if err != nil {
		return err
	}

	// Check any Go runtime modules.
	err = CheckRuntimeProviderGo(logger, config.Runtime.Path, paths)
	if err != nil {
		return err
	}

	// // Check any Lua runtime modules.
	// err = CheckRuntimeProviderLua(logger, config, paths)
	// if err != nil {
	// 	return err
	// }

	// // Check any JavaScript runtime modules.
	// err = CheckRuntimeProviderJavascript(logger, config)
	// if err != nil {
	// 	return err
	// }

	return nil
}
