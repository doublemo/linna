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

package main

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/doublemo/nana/runtime"
)

// build : go build --trimpath --mod=vendor --buildmode=plugin -o ./samples.so
func InitModule(ctx context.Context, log runtime.Logger, db *sql.DB, module runtime.Module, initializer runtime.Initializer) error {
	fmt.Println("-------------Hello World---------------")
	return nil
}
