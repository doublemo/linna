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
// Date: 2022-05-29 23:37:23
// LastEditors: Randyma
// LastEditTime: 2022-05-29 23:37:32
// Description:

package sd

import (
	"context"
	"sync"

	"google.golang.org/grpc/resolver"
)

type (
	// ResolverBuilder 用于grpc负载创建服务信息
	ResolverBuilder struct {
		scheme      string
		serviceName string
		endpointer  Endpointer
	}

	// dnsResolver GRPC负载信息处理与监听
	dnsResolver struct {
		serviceName string
		target      resolver.Target
		cc          resolver.ClientConn
		rn          chan struct{}
		ctx         context.Context
		ctxCancel   context.CancelFunc
		endpointer  Endpointer
		wg          sync.WaitGroup
	}
)

func (br *ResolverBuilder) Build(target resolver.Target, cc resolver.ClientConn, opts resolver.BuildOptions) (resolver.Resolver, error) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &dnsResolver{
		target:      target,
		cc:          cc,
		rn:          make(chan struct{}),
		ctx:         ctx,
		ctxCancel:   cancel,
		serviceName: br.serviceName,
		endpointer:  br.endpointer,
	}

	// 注册通知
	r.endpointer.Register(r.rn)

	r.wg.Add(1)
	go r.watch()
	r.resolve()
	return r, nil
}

func (br *ResolverBuilder) Scheme() string {
	return br.scheme
}

func NewResolverBuilder(scheme, serviceName string, endpointer Endpointer) *ResolverBuilder {
	return &ResolverBuilder{
		scheme:      scheme,
		serviceName: serviceName,
		endpointer:  endpointer,
	}
}

func (r *dnsResolver) watch() {
	defer func() {
		r.wg.Done()
	}()

	for {
		select {
		case <-r.ctx.Done():
			return

		case <-r.rn:
			r.resolve()
		}
	}
}

func (r *dnsResolver) resolve() {
	if r.endpointer == nil {
		return
	}

	endpoints, err := r.endpointer.Endpoints()
	if err != nil {
		return
	}

	addrs := make([]resolver.Address, 0)
	for _, endpoint := range endpoints {
		name := endpoint.Name()
		group := endpoint.Get("group")
		addr := endpoint.Addr()
		if name != r.target.Scheme || group != r.serviceName {
			continue
		}

		if len(addr) < 1 {
			continue
		}
		addrs = append(addrs, resolver.Address{Addr: addr})
	}

	r.cc.UpdateState(resolver.State{Addresses: addrs})
}

func (r *dnsResolver) ResolveNow(o resolver.ResolveNowOptions) {
	select {
	case r.rn <- struct{}{}:
	default:
	}
}

func (r *dnsResolver) Close() {
	r.endpointer.Deregister(r.rn)
	r.ctxCancel()
	r.wg.Wait()
}
