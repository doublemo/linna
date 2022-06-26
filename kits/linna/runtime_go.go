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
	"database/sql"
	"errors"
	"path/filepath"
	"plugin"
	"strings"

	"github.com/doublemo/nana/runtime"
	"go.uber.org/zap"
)

type RuntimeGo struct {
	ModulePaths []string
}

func NewRuntimeGo(ctx context.Context, log *zap.Logger, c RuntimeConfiguration, paths ...string) (*RuntimeGo, error) {
	modulePaths := make([]string, 0)
	for _, path := range paths {
		if strings.ToLower(filepath.Ext(path)) != ".so" {
			continue
		}

		relPath, name, fn, err := openGoModule(log, c.Path, path)
		if err != nil {
			return nil, err
		}

		if err := fn(ctx, nil, nil, nil, nil); err != nil {
			log.Fatal("Error returned by InitModule function in Go module", zap.String("name", name), zap.Error(err))
			return nil, errors.New("error returned by InitModule function in Go module")
		}
		modulePaths = append(modulePaths, relPath)
	}

	log.Info("Go runtime modules loaded")
	return &RuntimeGo{
		ModulePaths: modulePaths,
	}, nil
}

func openGoModule(log *zap.Logger, rootPath, path string) (string, string, runtime.InitModuleFn, error) {
	relPath, _ := filepath.Rel(rootPath, path)
	name := strings.TrimSuffix(relPath, filepath.Ext(relPath))

	// Open the plugin.
	p, err := plugin.Open(path)
	if err != nil {
		log.Error("Could not open Go module", zap.String("path", path), zap.Error(err))
		return "", "", nil, err
	}

	// Look up the required initialisation function.
	f, err := p.Lookup(runtime.INIT_MODULE_FUNC_NAME)
	if err != nil {
		log.Fatal("Error looking up InitModule function in Go module", zap.String("name", name))
		return "", "", nil, err
	}

	// Ensure the function has the correct signature.
	fn, ok := f.(func(context.Context, runtime.Logger, *sql.DB, runtime.Module, runtime.Initializer) error)
	if !ok {
		log.Fatal("Error reading InitModule function in Go module", zap.String("name", name))
		return "", "", nil, errors.New("error reading InitModule function in Go module")
	}

	return relPath, name, runtime.InitModuleFn(fn), nil
}
