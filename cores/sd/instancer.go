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
// Date: 2022-05-29 23:15:36
// LastEditors: Randyma
// LastEditTime: 2022-05-29 23:16:24
// Description:

package sd

type (
	// Event represents a push notification generated from the underlying service discovery
	// implementation. It contains either a full set of available resource instances, or
	// an error indicating some issue with obtaining information from discovery backend.
	// Examples of errors may include loosing connection to the discovery backend, or
	// trying to look up resource instances using an incorrectly formatted key.
	// After receiving an Event with an error the listenter should treat previously discovered
	// resource instances as stale (although it may choose to continue using them).
	// If the Instancer is able to restore connection to the discovery backend it must push
	// another Event with the current set of resource instances.
	Event struct {
		Instances []string
		Err       error
	}

	// Instancer listens to a service discovery system and notifies registered
	// observers of changes in the resource instances. Every event sent to the channels
	// contains a complete set of instances known to the Instancer. That complete set is
	// sent immediately upon registering the channel, and on any future updates from
	// discovery system.
	Instancer interface {
		Register(chan<- Event)
		Deregister(chan<- Event)
		Stop()
	}
)
