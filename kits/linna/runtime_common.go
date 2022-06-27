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

	"github.com/doublemo/nana/rtapi"
	"google.golang.org/grpc/codes"
)

type RuntimeRpcValues struct {
	Id          string
	Headers     map[string]string
	QueryParams map[string]string
	UserId      string
	Username    string
	Vars        map[string]string
	Expiry      int64
	SessionID   string
	ClientIP    string
	ClientPort  string
	Lang        string
}

type (
	RuntimeRpcFunction      func(ctx context.Context, rpcValues *RuntimeRpcValues, payload string) (codes.Code, string, error)
	RuntimeBeforeRtFunction func(ctx context.Context, rpcValues *RuntimeRpcValues, in *rtapi.Envelope) (*rtapi.Envelope, error)
	RuntimeAfterRtFunction  func(ctx context.Context, rpcValues *RuntimeRpcValues, out, in *rtapi.Envelope) error
)
