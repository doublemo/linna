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
	"strings"

	"github.com/doublemo/nana/rtapi"
	"github.com/doublemo/nana/runtime"
	"google.golang.org/grpc/codes"
)

// go 注册器
type RuntimeGoInitializer struct {
	node   string
	db     *sql.DB
	module runtime.Module
	logger runtime.Logger
	config RuntimeConfiguration

	rpc      map[string]RuntimeRpcFunction
	beforeRt map[string]RuntimeBeforeRtFunction
	afterRt  map[string]RuntimeAfterRtFunction
}

func (r *RuntimeGoInitializer) Rpc(id string) (fn RuntimeRpcFunction, ok bool) {
	fn, ok = r.rpc[id]
	return
}

func (ri *RuntimeGoInitializer) RegisterRpc(id string, fn func(ctx context.Context, logger runtime.Logger, db *sql.DB, m runtime.Module, payload string) (string, error)) error {
	id = strings.ToLower(id)
	ri.rpc[id] = func(ctx context.Context, rpcValues *RuntimeRpcValues, payload string) (codes.Code, string, error) {
		ctx = NewRuntimeGoContext(ctx, &RuntimeGoContextValues{
			RuntimeRpcValues: rpcValues,
			Env:              ri.config.Environment,
			Node:             ri.node,
		})

		result, fnErr := fn(ctx, ri.logger.WithField("rpc_id", id), ri.db, ri.module, payload)
		if fnErr != nil {
			return codes.Internal, result, fnErr
		}
		return codes.OK, result, nil
	}

	return nil
}

func (ri *RuntimeGoInitializer) RegisterBeforeRt(id string, fn func(ctx context.Context, logger runtime.Logger, db *sql.DB, m runtime.Module, envelope *rtapi.Envelope) (*rtapi.Envelope, error)) error {
	id = strings.ToLower(id)
	ri.beforeRt[id] = func(ctx context.Context, rpcValues *RuntimeRpcValues, envelope *rtapi.Envelope) (*rtapi.Envelope, error) {
		ctx = NewRuntimeGoContext(ctx, &RuntimeGoContextValues{
			RuntimeRpcValues: rpcValues,
			Env:              ri.config.Environment,
			Node:             ri.node,
		})

		loggerFields := map[string]interface{}{"api_id": id}
		return fn(ctx, ri.logger.WithFields(loggerFields), ri.db, ri.module, envelope)
	}
	return nil
}

func (ri *RuntimeGoInitializer) RegisterAfterRt(id string, fn func(ctx context.Context, logger runtime.Logger, db *sql.DB, nk runtime.Module, out, in *rtapi.Envelope) error) error {
	id = strings.ToLower(id)
	ri.afterRt[id] = func(ctx context.Context, rpcValues *RuntimeRpcValues, out, in *rtapi.Envelope) error {
		ctx = NewRuntimeGoContext(ctx, &RuntimeGoContextValues{
			RuntimeRpcValues: rpcValues,
			Env:              ri.config.Environment,
			Node:             ri.node,
		})

		loggerFields := map[string]interface{}{"api_id": id}
		return fn(ctx, ri.logger.WithFields(loggerFields), ri.db, ri.module, out, in)
	}
	return nil
}

func (ri *RuntimeGoInitializer) RegisterEvent() {}
