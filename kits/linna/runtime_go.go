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
// Reference: https://github.com/heroiclabs/nakama

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

//  NewRuntimeProviderGo 创建Go
func NewRuntimeProviderGo(ctx context.Context) {}

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
