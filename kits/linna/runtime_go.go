// Copyright (c) 2021 The Nakama Authors.
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

	"github.com/doublemo/linna-common/api"
	"github.com/doublemo/linna-common/runtime"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// RuntimeGoInitializer go插件初始化容器
type RuntimeGoInitializer struct {
	logger runtime.Logger
	db     *sql.DB
	env    map[string]string
	node   string
	na     runtime.LinnaModule

	execution *RuntimeExecution
	modules   []string
}

func (ri *RuntimeGoInitializer) RegisterRpc(id string, fn func(ctx context.Context, logger runtime.Logger, db *sql.DB, na runtime.LinnaModule, payload string) (string, error)) error {
	id = strings.ToLower(id)
	ri.execution.Rpc[id] = func(ctx context.Context, logger *zap.Logger, r *RuntimeSameRequest, payload string) (string, error, codes.Code) {
		ctx = NewRuntimeGoContext(ctx, RuntimeExecutionModeRPC, NewRuntimeContextConfigurationFromSameRequest(ri.node, ri.env, r))
		result, fnErr := fn(ctx, ri.logger.WithField("rpc_id", id), ri.db, ri.na, payload)
		if fnErr != nil {
			if runtimeErr, ok := fnErr.(*runtime.Error); ok {
				if runtimeErr.Code <= 0 || runtimeErr.Code >= 17 {
					// If error is present but code is invalid then default to 13 (Internal) as the error code.
					return result, runtimeErr, codes.Internal
				}
				return result, runtimeErr, codes.Code(runtimeErr.Code)
			}
			// Not a runtime error that contains a code.
			return result, fnErr, codes.Internal
		}

		return result, nil, codes.OK
	}
	return nil
}

func (ri *RuntimeGoInitializer) Execution() *RuntimeExecution {
	return ri.execution
}

func (ri *RuntimeGoInitializer) Modules() []string {
	return ri.modules
}

//  NewRuntimeProviderGo 创建Go
func NewRuntimeProviderGo(ctx context.Context, c *RuntimeProviderConfiguration) (*RuntimeGoInitializer, error) {
	runtimeLogger := NewRuntimeGoLogger(c.Logger)
	logger := c.Logger
	startupLogger := c.StartupLogger
	config := c.Config
	runtimeConfig := config.Runtime
	node := config.Endpoint.Name
	env := runtimeConfig.Environment
	eventQueue := NewRuntimeEventQueue(logger, config)
	na := NewRuntimeGoLinnaModule(&RuntimeGoLinnaModuleOptions{
		Logger:             logger,
		DB:                 c.DB,
		ProtojsonMarshaler: c.ProtojsonMarshaler,
		Config:             c.Config,
		Node:               node,
	})

	initializer := &RuntimeGoInitializer{
		logger: runtimeLogger,
		db:     c.DB,
		env:    env,
		node:   node,

		execution: NewRuntimeExecution(),
	}

	ctx = NewRuntimeGoContext(ctx, RuntimeExecutionModeRunOnce, &RuntimeContextConfiguration{
		Env: runtimeConfig.Environment,
	})

	startupLogger.Info("Initialising Go runtime provider", zap.String("path", runtimeConfig.Path))
	modules := make([]string, 0)
	for _, path := range c.Paths {
		if strings.ToLower(filepath.Ext(path)) != ".so" {
			continue
		}

		relPath, name, fn, err := openGoModule(startupLogger, runtimeConfig.Path, path)
		if err != nil {
			return nil, err
		}

		if err := fn(ctx, runtimeLogger, c.DB, na, initializer); err != nil {
			startupLogger.Fatal("Error returned by InitModule function in Go module", zap.String("name", name), zap.Error(err))
			return nil, err
		}

		modules = append(modules, relPath)
	}
	
	startupLogger.Info("Go runtime modules loaded")
	events := &RuntimeEventFunctions{}
	if len(initializer.execution.EventFunctions) > 0 {
		events.eventFunction = func(ctx context.Context, evt *api.Event) {
			eventQueue.Queue(func() {
				for _, fn := range initializer.execution.EventFunctions {
					fn(ctx, initializer.logger, evt)
				}
			})
		}
		na.SetEventFn(events.eventFunction)
	}

	if len(initializer.execution.SessionStartFunctions) > 0 {
		events.sessionStartFunction = func(r *RuntimeSameRequest, evtTimeSec int64) {
			ctx := NewRuntimeGoContext(context.Background(), RuntimeExecutionModeEvent, NewRuntimeContextConfigurationFromSameRequest(node, env, r))
			evt := &api.Event{
				Name:      "session_start",
				Timestamp: &timestamppb.Timestamp{Seconds: evtTimeSec},
			}

			eventQueue.Queue(func() {
				for _, fn := range initializer.execution.SessionStartFunctions {
					fn(ctx, initializer.logger, evt)
				}
			})
		}
	}

	if len(initializer.execution.SessionEndFunctions) > 0 {
		events.sessionEndFunction = func(r *RuntimeSameRequest, evtTimeSec int64, reason string) {
			ctx := NewRuntimeGoContext(context.Background(), RuntimeExecutionModeEvent, NewRuntimeContextConfigurationFromSameRequest(node, env, r))
			evt := &api.Event{
				Name:       "session_end",
				Properties: map[string]string{"reason": reason},
				Timestamp:  &timestamppb.Timestamp{Seconds: evtTimeSec},
			}

			eventQueue.Queue(func() {
				for _, fn := range initializer.execution.SessionEndFunctions {
					fn(ctx, initializer.logger, evt)
				}
			})
		}
	}

	initializer.modules = modules
	c.EventFn = events
	return initializer, nil
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
