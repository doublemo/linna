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
// Date: 2022-05-29 23:35:22
// LastEditors: Randyma
// LastEditTime: 2022-05-29 23:35:44
// Description:

package sd

// Registrar registers instance information to a service discovery system when
// an instance becomes alive and healthy, and deregisters that information when
// the service becomes unhealthy or goes away.
//
// Registrar implementations exist for various service discovery systems. Note
// that identifying instance information (e.g. host:port) must be given via the
// concrete constructor; this interface merely signals lifecycle changes.
type Registrar interface {
	Register() error
	Deregister() error
}
