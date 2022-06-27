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
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

// 运行时
type Runtime struct {
	runtimeGo *RuntimeGo
}

func (r *Runtime) Rpc(id string) (RuntimeRpcFunction, bool) {
	initializer := r.runtimeGo.GetInitializer()
	fn, ok := initializer.Rpc(id)
	if !ok {
		return nil, false
	}
	return fn, true
}

func NewRuntime(ctx context.Context, log *zap.Logger, c Configuration) (*Runtime, error) {
	paths, err := scanRuntimePath(log, c.Runtime.Path)
	if err != nil {
		return nil, err
	}

	log.Info("Initialising runtime event queue processor", zap.Any("paths", paths))

	runtimeGo, err := NewRuntimeGo(ctx, log, c.Runtime, paths...)
	if err != nil {
		return nil, err
	}

	return &Runtime{
		runtimeGo: runtimeGo,
	}, nil
}

// 扫描运行时path 目录
func scanRuntimePath(logger *zap.Logger, rootpath string) ([]string, error) {
	if err := os.MkdirAll(rootpath, os.ModePerm); err != nil {
		return nil, err
	}

	paths := make([]string, 0, 5)
	if err := filepath.Walk(rootpath, func(path string, f os.FileInfo, err error) error {
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
