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
// Date: 2022-05-09 09:53:09
// LastEditors: randyma
// LastEditTime: 2022-05-12 10:41:22
// Description:

package linna

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"plugin"
	"strings"

	"github.com/doublemo/linna-common/runtime"
	"go.uber.org/zap"
)

// RuntimeGoInitializer go插件初始化容器
type RuntimeGoInitializer struct {
	logger runtime.Logger
	db     *sql.DB
	env    map[string]string
	na     runtime.LinnaModule
}

func (ri *RuntimeGoInitializer) RegisterEvent()             {}
func (ri *RuntimeGoInitializer) RegisterEventSessionStart() {}
func (ri *RuntimeGoInitializer) RegisterEventSessionEnd()   {}
func (ri *RuntimeGoInitializer) RegisterRPC()               {}

type RuntimeProviderGoOptions struct {
	logger        *zap.Logger
	startupLogger *zap.Logger
	config        Configuration
	paths         []string
	rootPath      string
	queue         *RuntimeEventQueue
	db            *sql.DB
}

//  NewRuntimeProviderGo 创建Go
func NewRuntimeProviderGo(ctx context.Context, option *RuntimeProviderGoOptions) ([]string, *RuntimeGoInitializer, error) {
	runtimeLogger := NewRuntimeGoLogger(option.logger)
	// node := config.Endpoint.Name
	// env := config.Runtime.Environment
	// na :=

	initializer := &RuntimeGoInitializer{
		logger: runtimeLogger,
		db:     option.db,
	}

	modules := make([]string, 0)
	for _, path := range option.paths {
		if strings.ToLower(filepath.Ext(path)) != ".so" {
			continue
		}

		relPath, name, fn, err := openGoModule(option.startupLogger, option.rootPath, path)
		if err != nil {
			return nil, nil, err
		}

		if err := fn(ctx, runtimeLogger, option.db, nil, nil); err != nil {
			option.startupLogger.Fatal("Error returned by InitModule function in Go module", zap.String("name", name), zap.Error(err))
			return nil, nil, err
		}

		modules = append(modules, relPath)
	}

	option.startupLogger.Info("Go runtime modules loaded")
	return modules, initializer, nil
}

// CheckRuntimeProviderGo 检查Go插件
func CheckRuntimeProviderGo(logger *zap.Logger, rootPath string, paths []string) error {
	for _, path := range paths {
		// Skip everything except shared object files.
		if strings.ToLower(filepath.Ext(path)) != ".so" {
			continue
		}

		// Open the plugin, and look up the required initialisation function.
		// The function isn't used here, all we need is a type/signature check.
		_, _, _, err := openGoModule(logger, rootPath, path)
		if err != nil {
			// Errors are already logged in the function above.
			return err
		}
	}

	return nil
}

// runtime.Logger, *sql.DB, runtime.Module, runtime.Initializer
func openGoModule(logger *zap.Logger, rootPath, path string) (string, string, func(context.Context, runtime.Logger, *sql.DB, runtime.LinnaModule, runtime.Initializer) error, error) {
	relPath, _ := filepath.Rel(rootPath, path)
	name := strings.TrimSuffix(relPath, filepath.Ext(relPath))

	// Open the plugin.
	p, err := plugin.Open(path)
	if err != nil {
		logger.Error("Could not open Go module", zap.String("path", path), zap.Error(err))
		return "", "", nil, err
	}

	// Look up the required initialisation function.
	f, err := p.Lookup("InitModule")
	if err != nil {
		logger.Fatal("Error looking up InitModule function in Go module", zap.String("name", name))
		return "", "", nil, err
	}

	// Ensure the function has the correct signature.
	fn, ok := f.(func(context.Context, runtime.Logger, *sql.DB, runtime.LinnaModule, runtime.Initializer) error)
	if !ok {
		logger.Fatal("Error reading InitModule function in Go module", zap.String("name", name))
		return "", "", nil, errors.New("error reading InitModule function in Go module")
	}

	return relPath, name, fn, nil
}
