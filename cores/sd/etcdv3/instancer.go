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
// Date: 2022-05-29 23:47:50
// LastEditors: Randyma
// LastEditTime: 2022-05-29 23:48:07
// Description:

package etcdv3

import (
	"log"

	"github.com/doublemo/linna/cores/sd"
	"github.com/doublemo/linna/cores/sd/internal/instance"
)

// Instancer yields instances stored in a certain etcd keyspace. Any kind of
// change in that keyspace is watched and will update the Instancer's Instancers.
type Instancer struct {
	cache  *instance.Cache
	client Client
	prefix string
	quitc  chan struct{}
}

// NewInstancer returns an etcd instancer. It will start watching the given
// prefix for changes, and update the subscribers.
func NewInstancer(c Client, prefix string) (*Instancer, error) {
	s := &Instancer{
		cache:  instance.NewCache(),
		client: c,
		prefix: prefix,
		quitc:  make(chan struct{}),
	}

	instances, err := s.client.GetEntries(s.prefix)
	if err != nil {
		log.Println("err:", err)
	}

	s.cache.Update(sd.Event{Instances: instances, Err: err})
	go s.loop()
	return s, nil
}

func (s *Instancer) loop() {
	ch := make(chan struct{})
	go s.client.WatchPrefix(s.prefix, ch)

	for {
		select {
		case <-ch:
			instances, err := s.client.GetEntries(s.prefix)
			if err != nil {
				log.Println("msg", "failed to retrieve entries", "err", err)
				s.cache.Update(sd.Event{Err: err})
				continue
			}
			s.cache.Update(sd.Event{Instances: instances})

		case <-s.quitc:
			return
		}
	}
}

// Stop terminates the Instancer.
func (s *Instancer) Stop() {
	close(s.quitc)
}

// Register implements Instancer.
func (s *Instancer) Register(ch chan<- sd.Event) {
	s.cache.Register(ch)
}

// Deregister implements Instancer.
func (s *Instancer) Deregister(ch chan<- sd.Event) {
	s.cache.Deregister(ch)
}
