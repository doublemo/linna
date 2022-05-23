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
// Date: 2022-05-23 10:09:49
// LastEditors: randyma
// LastEditTime: 2022-05-23 10:09:53
// Description:

package linna

import (
	"context"
	"database/sql"
	"strings"

	"github.com/doublemo/linna-common/api"
	"github.com/doublemo/linna-common/rtapi"
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
	RuntimeBeforeRtFunction          func(ctx context.Context, logger *zap.Logger, r *RuntimeSameRequest, in *rtapi.Envelope) (*rtapi.Envelope, error)
	RuntimeAfterRtFunction           func(ctx context.Context, logger *zap.Logger, r *RuntimeSameRequest, out, in *rtapi.Envelope) error
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
	RegisterRPC(ctx context.Context, id string, r *RuntimeSameRequest, payload string) (string, error, codes.Code)
	Execution() *RuntimeExecution
	Modules() []string
}
