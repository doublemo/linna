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
// Date: 2022-05-12 09:58:12
// LastEditors: randyma
// LastEditTime: 2022-05-12 10:35:19
// Description: 系统信号处理

package cores

type SignalCommand int

// 定义信息参数
const (
	SignalINT SignalCommand = (iota + 1) << 1
	SignalTERM
	SignalUSR1
	SignalUSR2
	SignalHUP
)
