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
// Date: 2022-05-29 23:10:26
// LastEditors: Randyma
// LastEditTime: 2022-05-29 23:10:59
// Description: 节点信息缓存

package sd

import (
	"sort"
	"sync"
	"time"
)

// endpointCache collects the most recent set of instances from a service discovery
// system, creates endpoints for them using a factory function, and makes
// them available to consumers.
type endpointCache struct {
	options            endpointerOptions
	mtx                sync.RWMutex
	err                error
	endpoints          []Endpoint
	invalidateDeadline time.Time
	timeNow            func() time.Time
}

// newEndpointCache returns a new, empty endpointCache.
func newEndpointCache(options endpointerOptions) *endpointCache {
	return &endpointCache{
		options: options,
		timeNow: time.Now,
	}
}

// Update should be invoked by clients with a complete set of current instance
// strings whenever that set changes. The cache manufactures new endpoints via
// the factory, closes old endpoints when they disappear, and persists existing
// endpoints if they survive through an update.
func (c *endpointCache) Update(event Event) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	// Happy path.
	if event.Err == nil {
		c.updateCache(event.Instances)
		c.err = nil
		return
	}

	// Sad path. Something's gone wrong in sd.
	if !c.options.invalidateOnError {
		return // keep returning the last known endpoints on error
	}
	if c.err != nil {
		return // already in the error state, do nothing & keep original error
	}
	c.err = event.Err
	// set new deadline to invalidate Endpoints unless non-error Event is received
	c.invalidateDeadline = c.timeNow().Add(c.options.invalidateTimeout)
	return
}

func (c *endpointCache) updateCache(instances []string) {
	// Deterministic order (for later).
	sort.Strings(instances)

	// Populate the slice of endpoints.
	endpoints := make([]Endpoint, 0)
	for _, instance := range instances {
		endpoint := &EndpointLocal{}
		if err := endpoint.Unmarshal(instance); err != nil {
			continue
		}
		endpoints = append(endpoints, endpoint)
	}

	// Swap and trigger GC for old copies.
	c.endpoints = endpoints
}

// Endpoints yields the current set of (presumably identical) endpoints, ordered
// lexicographically by the corresponding instance string.
func (c *endpointCache) Endpoints() ([]Endpoint, error) {
	// in the steady state we're going to have many goroutines calling Endpoints()
	// concurrently, so to minimize contention we use a shared R-lock.
	c.mtx.RLock()

	if c.err == nil || c.timeNow().Before(c.invalidateDeadline) {
		defer c.mtx.RUnlock()
		return c.endpoints, nil
	}

	c.mtx.RUnlock()

	// in case of an error, switch to an exclusive lock.
	c.mtx.Lock()
	defer c.mtx.Unlock()

	// re-check condition due to a race between RUnlock() and Lock().
	if c.err == nil || c.timeNow().Before(c.invalidateDeadline) {
		return c.endpoints, nil
	}

	c.updateCache(nil) // close any remaining active endpoints
	return nil, c.err
}
