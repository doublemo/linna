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
	"errors"
	"sync"
	"time"

	"github.com/doublemo/linna-common/api"
	"github.com/doublemo/linna/internal/metrics"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
)

// RuntimeGoLinnaModuleConfiguration 运行时间创建module参数
type RuntimeGoLinnaModuleConfiguration struct {
	Logger             *zap.Logger
	DB                 *sql.DB
	ProtojsonMarshaler *protojson.MarshalOptions
	Config             Configuration
	Node               string
	Metrics            metrics.Metrics
}

// RuntimeGoLinnaModule 运行Linna模块
type RuntimeGoLinnaModule struct {
	sync.RWMutex
	logger             *zap.Logger
	db                 *sql.DB
	protojsonMarshaler *protojson.MarshalOptions
	config             Configuration
	metrics            metrics.Metrics

	eventFn RuntimeEventCustomFunction
	node    string
}

func NewRuntimeGoLinnaModule(c *RuntimeGoLinnaModuleConfiguration) *RuntimeGoLinnaModule {
	return &RuntimeGoLinnaModule{
		logger:             c.Logger,
		db:                 c.DB,
		protojsonMarshaler: c.ProtojsonMarshaler,
		config:             c.Config,
		node:               c.Node,
		metrics:            c.Metrics,
	}
}

func (n *RuntimeGoLinnaModule) Authenticate(ctx context.Context, token, username string, create bool) (string, string, bool, error) {
	return "", "", false, nil
}

// @group events
// @summary Generate an event.
// @param ctx(type=context.Context) The context object represents information about the server and requester.
// @param evt(type=*api.Event) The event to be generated.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeGoLinnaModule) Event(ctx context.Context, evt *api.Event) error {
	if ctx == nil {
		return errors.New("expects a non-nil context")
	}
	if evt == nil {
		return errors.New("expects a non-nil event")
	}

	n.RLock()
	fn := n.eventFn
	n.RUnlock()
	if fn != nil {
		fn(ctx, evt)
	}

	return nil
}

// @group metrics
// @summary Add a custom metrics counter.
// @param name(type=string) The name of the custom metrics counter.
// @param tags(type=map[string]string) The metrics tags associated with this counter.
// @param delta(type=int64) Value to update this metric with.
func (n *RuntimeGoLinnaModule) MetricsCounterAdd(name string, tags map[string]string, delta int64) {
	n.metrics.CustomCounter(name, tags, delta)
}

// @group metrics
// @summary Add a custom metrics gauge.
// @param name(type=string) The name of the custom metrics gauge.
// @param tags(type=map[string]string) The metrics tags associated with this gauge.
// @param value(type=float64) Value to update this metric with.
func (n *RuntimeGoLinnaModule) MetricsGaugeSet(name string, tags map[string]string, value float64) {
	n.metrics.CustomGauge(name, tags, value)
}

// @group metrics
// @summary Add a custom metrics timer.
// @param name(type=string) The name of the custom metrics timer.
// @param tags(type=map[string]string) The metrics tags associated with this timer.
// @param value(type=time.Duration) Value to update this metric with.
func (n *RuntimeGoLinnaModule) MetricsTimerRecord(name string, tags map[string]string, value time.Duration) {
	n.metrics.CustomTimer(name, tags, value)
}

func (n *RuntimeGoLinnaModule) SetEventFn(fn RuntimeEventCustomFunction) {
	n.Lock()
	n.eventFn = fn
	n.Unlock()
}
