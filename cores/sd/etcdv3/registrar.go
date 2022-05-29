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
// Author: Randyma
// Date: 2022-05-29 23:49:59
// LastEditors: Randyma
// LastEditTime: 2022-05-29 23:50:14
// Description:

package etcdv3

import (
	"sync"
	"time"

	"github.com/doublemo/linna/cores/sd"
)

const minHeartBeatTime = 500 * time.Millisecond

type (
	// Service holds the instance identifying data you want to publish to etcd. Key
	// must be unique, and value is the string returned to subscribers, typically
	// called the "instance" string in other parts of package sd.
	Service struct {
		Prefix   string      // unique key, e.g. "/service/foobar/1.2.3.4:8080"
		Endpoint sd.Endpoint // returned to subscribers, e.g. "http://1.2.3.4:8080"
		TTL      *TTLOption
	}

	// TTLOption allow setting a key with a TTL. This option will be used by a loop
	// goroutine which regularly refreshes the lease of the key.
	TTLOption struct {
		heartbeat time.Duration // e.g. time.Second * 3
		ttl       time.Duration // e.g. time.Second * 10
	}

	// Registrar registers service instance liveness information to etcd.
	Registrar struct {
		client  Client
		service Service
		quitmtx sync.Mutex
		quit    chan struct{}
	}
)

func (s Service) Key() string {
	return s.Prefix + "/" + s.Endpoint.Name() + "/" + s.Endpoint.ID()
}

func (s Service) Value() string {
	return s.Endpoint.Marshal()
}

// NewTTLOption returns a TTLOption that contains proper TTL settings. Heartbeat
// is used to refresh the lease of the key periodically; its value should be at
// least 500ms. TTL defines the lease of the key; its value should be
// significantly greater than heartbeat.
//
// Good default values might be 3s heartbeat, 10s TTL.
func NewTTLOption(heartbeat, ttl time.Duration) *TTLOption {
	if heartbeat <= minHeartBeatTime {
		heartbeat = minHeartBeatTime
	}
	if ttl <= heartbeat {
		ttl = 3 * heartbeat
	}
	return &TTLOption{
		heartbeat: heartbeat,
		ttl:       ttl,
	}
}

// NewRegistrar returns a etcd Registrar acting on the provided catalog
// registration (service).
func NewRegistrar(client Client, service Service) *Registrar {
	return &Registrar{
		client:  client,
		service: service,
	}
}

// Register implements the sd.Registrar interface. Call it when you want your
// service to be registered in etcd, typically at startup.
func (r *Registrar) Register() error {
	return r.client.Register(r.service)
}

// Deregister implements the sd.Registrar interface. Call it when you want your
// service to be deregistered from etcd, typically just prior to shutdown.
func (r *Registrar) Deregister() error {
	if err := r.client.Deregister(r.service); err != nil {
		return err
	}

	r.quitmtx.Lock()
	defer r.quitmtx.Unlock()
	if r.quit != nil {
		close(r.quit)
		r.quit = nil
	}
	return nil
}
