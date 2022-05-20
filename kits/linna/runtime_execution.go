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
// Date: 2022-05-18 10:15:02
// LastEditors: randyma
// LastEditTime: 2022-05-18 11:18:53
// Description: 通用类型定义

package linna

import (
	"context"
	"database/sql"
	"reflect"
	"strings"

	"github.com/doublemo/linna-common/api"
	"github.com/doublemo/linna-common/runtime"
	"github.com/doublemo/linna/internal/metrics"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
)

const API_PREFIX = "/linna.api.Linna/"
const RTAPI_PREFIX = "*rtapi.Envelope_"

var API_PREFIX_LOWERCASE = strings.ToLower(API_PREFIX)
var RTAPI_PREFIX_LOWERCASE = strings.ToLower(RTAPI_PREFIX)

// RuntimeSameRequest 运行时调用方法参数
type RuntimeSameRequest struct {
	Headers     map[string][]string
	QueryParams map[string][]string
	UserID      uint64
	Username    string
	Vars        map[string]string
	Expiry      int64
	ClientIP    string
	ClientPort  string
	Lang        string
	SessionID   string
}

// RuntimeContextConfiguration 运行时上下文通用配置参数
type RuntimeContextConfiguration struct {
	Node          string              // 节点
	Env           map[string]string   // 环境变量
	Headers       map[string][]string // 头信息
	QueryParams   map[string][]string // 参数
	SessionID     string              // 会话ID
	SessionExpiry int64               // 会话过期时间
	UserID        uint64              // 用户ID
	Username      string              // 用户
	Vars          map[string]string   //
	ClientIP      string              // 客户IP
	ClientPort    string              // 客户端端口
	Lang          string              // 语言
}

func NewRuntimeContextConfigurationFromSameRequest(node string, env map[string]string, r *RuntimeSameRequest) *RuntimeContextConfiguration {
	return &RuntimeContextConfiguration{
		Node:          node,
		Env:           env,
		Headers:       r.Headers,
		QueryParams:   r.QueryParams,
		SessionID:     r.SessionID,
		SessionExpiry: r.Expiry,
		UserID:        r.UserID,
		Username:      r.Username,
		Vars:          r.Vars,
		ClientIP:      r.ClientIP,
		ClientPort:    r.ClientPort,
		Lang:          r.Lang,
	}
}

// RuntimeProviderConfiguration 运行配置
type RuntimeProviderConfiguration struct {
	Logger               *zap.Logger
	StartupLogger        *zap.Logger
	DB                   *sql.DB
	ProtojsonMarshaler   *protojson.MarshalOptions
	ProtojsonUnmarshaler *protojson.UnmarshalOptions
	Config               Configuration
	Metrics              metrics.Metrics

	EventFn *RuntimeEventFunctions
	Paths   []string
}

type (
	RuntimeRpcFunction               func(ctx context.Context, logger *zap.Logger, r *RuntimeSameRequest, payload string) (string, error, codes.Code)
	RuntimeBeforeRtFunction          func(ctx context.Context, logger *zap.Logger, r *RuntimeSameRequest, payload string) (string, error, codes.Code)
	RuntimeAfterRtFunction           func(ctx context.Context, logger *zap.Logger, r *RuntimeSameRequest, payload string) (string, error, codes.Code)
	RuntimeEventCustomFunction       func(ctx context.Context, evt *api.Event)
	RuntimeEventFunction             func(ctx context.Context, logger runtime.Logger, evt *api.Event)
	RuntimeEventSessionStartFunction func(r *RuntimeSameRequest, evtTimeSec int64)
	RuntimeEventSessionEndFunction   func(r *RuntimeSameRequest, evtTimeSec int64, reason string)
)

// RuntimeBeforeReqFunctions 运行时调用方法前
type RuntimeBeforeReqFunctions struct{}

// RuntimeAfterReqFunctions运行时调用方法后
type RuntimeAfterReqFunctions struct{}

// RuntimeEventFunctions 运行时事件处理函数
type RuntimeEventFunctions struct {
	sessionStartFunction RuntimeEventSessionStartFunction
	sessionEndFunction   RuntimeEventSessionEndFunction
	eventFunction        RuntimeEventCustomFunction
}

// RuntimeProvider
type RuntimeProvider interface {
	Rpc(ctx context.Context, id string, r *RuntimeSameRequest, payload string) (string, error, codes.Code)
}

type RuntimeExecution struct {
	Rpc                   map[string]RuntimeRpcFunction
	BeforeRtFunctions     map[string]RuntimeBeforeRtFunction
	AfterRtFunctions      map[string]RuntimeAfterRtFunction
	BeforeReqFunctions    *RuntimeBeforeReqFunctions
	AfterReqFunctions     *RuntimeAfterReqFunctions
	EventFunctions        []RuntimeEventFunction
	SessionStartFunctions []RuntimeEventFunction
	SessionEndFunctions   []RuntimeEventFunction
}

func NewRuntimeExecution() *RuntimeExecution {
	return &RuntimeExecution{
		Rpc:                make(map[string]RuntimeRpcFunction),
		BeforeRtFunctions:  make(map[string]RuntimeBeforeRtFunction),
		AfterRtFunctions:   make(map[string]RuntimeAfterRtFunction),
		BeforeReqFunctions: &RuntimeBeforeReqFunctions{},
		AfterReqFunctions:  &RuntimeAfterReqFunctions{},
	}
}

func RegisterRuntimeExecution(provider RuntimeProvider, re *RuntimeExecution) func(mode RuntimeExecutionMode, id string) {
	return func(mode RuntimeExecutionMode, id string) {
		switch mode {
		case RuntimeExecutionModeRPC:
			re.Rpc[id] = func(ctx context.Context, logger *zap.Logger, r *RuntimeSameRequest, payload string) (string, error, codes.Code) {
				return provider.Rpc(ctx, id, r, payload)
			}

		case RuntimeExecutionModeBefore:
		case RuntimeExecutionModeAfter:
		}
	}
}

func runtimeExecutionMerge(name string, logger *zap.Logger, desc, src *RuntimeExecution) *RuntimeExecution {
	for k, v := range src.Rpc {
		logger.Info("Registered "+name+" runtime RPC function invocation", zap.String("id", k))
		desc.Rpc[k] = v
	}

	for k, v := range src.BeforeRtFunctions {
		logger.Info("Registered "+name+" runtime Before function invocation", zap.String("id", k))
		desc.BeforeRtFunctions[k] = v
	}

	for k, v := range src.AfterRtFunctions {
		logger.Info("Registered "+name+" runtime After function invocation", zap.String("id", k))
		desc.AfterRtFunctions[k] = v
	}
	mergeBeforeOrAfterFunctions(name, "Before", logger, desc.BeforeReqFunctions, src.BeforeReqFunctions)
	mergeBeforeOrAfterFunctions(name, "After", logger, desc.AfterReqFunctions, src.AfterReqFunctions)
	return nil
}

func mergeBeforeOrAfterFunctions[T *RuntimeBeforeReqFunctions | *RuntimeAfterReqFunctions](name, sub string, logger *zap.Logger, dest, src T) {
	t := reflect.ValueOf(dest).Elem()
	tp := reflect.TypeOf(dest).Elem()
	s := reflect.ValueOf(src).Elem()
	for i := 0; i < t.NumField(); i++ {
		if !s.Field(i).IsNil() {
			logger.Info("Registered "+name+" runtime "+sub+" function invocation", zap.String("id", tp.Field(i).Name))
			t.Field(i).Set(s.Field(i))
		}
	}
}
