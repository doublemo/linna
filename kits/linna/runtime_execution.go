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
	"strings"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
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

type (
	RuntimeRpcFunction      func(ctx context.Context, logger *zap.Logger, r *RuntimeSameRequest, payload string) (string, error, codes.Code)
	RuntimeBeforeRtFunction func(ctx context.Context, logger *zap.Logger, r *RuntimeSameRequest, payload string) (string, error, codes.Code)
	RuntimeAfterRtFunction  func(ctx context.Context, logger *zap.Logger, r *RuntimeSameRequest, payload string) (string, error, codes.Code)
)

// RuntimeBeforeReqFunctions 运行时调用方法前
type RuntimeBeforeReqFunctions struct{}

// RuntimeAfterReqFunctions运行时调用方法后
type RuntimeAfterReqFunctions struct{}

// RuntimeEventFunctions 运行时事件处理函数
type RuntimeEventFunctions struct{}

// RuntimeProvider
type RuntimeProvider interface {
	Rpc(ctx context.Context, id string, r *RuntimeSameRequest, payload string) (string, error, codes.Code)
}

type RuntimeExecution struct {
	Rpc                map[string]RuntimeRpcFunction
	BeforeRtFunctions  map[string]RuntimeBeforeRtFunction
	AfterRtFunctions   map[string]RuntimeAfterRtFunction
	BeforeReqFunctions *RuntimeBeforeReqFunctions
	AfterReqFunctions  *RuntimeAfterReqFunctions
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
