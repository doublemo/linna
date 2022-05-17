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
// Date: 2022-05-09 09:56:47
// LastEditors: randyma
// LastEditTime: 2022-05-12 10:41:16
// Description:

package linna

import (
	"context"
	"database/sql"
	"sync"

	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
)

// RuntimeGoLinnaModuleOptions 运行时间创建module参数
type RuntimeGoLinnaModuleOptions struct {
	Logger             *zap.Logger
	DB                 *sql.DB
	ProtojsonMarshaler *protojson.MarshalOptions
	Config             Configuration
	Node               string
}

// RuntimeGoLinnaModule 运行Linna模块
type RuntimeGoLinnaModule struct {
	sync.RWMutex
	logger             *zap.Logger
	db                 *sql.DB
	protojsonMarshaler *protojson.MarshalOptions
	config             Configuration

	//eventFn RuntimeEventCustomFunction
	node string
}

func NewRuntimeGoLinnaModule(option *RuntimeGoLinnaModuleOptions) *RuntimeGoLinnaModule {
	return &RuntimeGoLinnaModule{
		logger:             option.Logger,
		db:                 option.DB,
		protojsonMarshaler: option.ProtojsonMarshaler,
		config:             option.Config,
		node:               option.Node,
	}
}

func (n *RuntimeGoLinnaModule) Authenticate(ctx context.Context, token, username string, create bool) (string, string, bool, error) {
	return "", "", false, nil
}
