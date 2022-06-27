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
	"database/sql"
	"fmt"

	"github.com/doublemo/linna/internal/metrics"
	"go.uber.org/zap"
)

type RuntimeGoModule struct {
	node    string
	logger  *zap.Logger
	config  Configuration
	db      *sql.DB
	metrics metrics.Metrics
}

func (rm *RuntimeGoModule) AuthenticateEmail() {
	fmt.Println("--- AuthenticateEmail --")
}

func NewRuntimeGoModule(log *zap.Logger, db *sql.DB, metrics metrics.Metrics, c Configuration) *RuntimeGoModule {
	return &RuntimeGoModule{
		node:    c.Name,
		logger:  log,
		config:  c,
		db:      db,
		metrics: metrics,
	}
}
