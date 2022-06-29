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

package linna

import (
	"flag"
	"fmt"
	"os"

	"github.com/doublemo/linna/cores/flags"
	"go.uber.org/zap"
)

// ParseArgs 参数解析
func ParseArgs(log *zap.Logger, v, commitid, buildAt string, args []string) *Configuration {
	if len(args) > 1 {
		switch args[1] {
		case "--version", "-v":
			fmt.Printf("%s + %s + %s\n", v, commitid, buildAt)
			os.Exit(0)

		case "migrate":
			os.Exit(0)
		}
	}

	configFilePath := NewConfiguration(log)
	configFileFlagSet := flag.NewFlagSet("linna", flag.ExitOnError)
	configFileFlagMaker := flags.NewFlagMakerFlagSet(&flags.FlagMakingOptions{
		UseLowerCase: true,
		Flatten:      false,
		TagName:      "yaml",
		TagUsage:     "usage",
	}, configFileFlagSet)

	if _, err := configFileFlagMaker.ParseArgs(configFilePath, args[1:]); err != nil {
		log.Fatal("Could not parse command line arguments", zap.Error(err))
	}

	mainConfig := NewConfiguration(log)
	mainConfig.Config = configFilePath.Config
	if err := mainConfig.Parse(); err != nil {
		log.Fatal("could not parse config file", zap.Error(err))
	}

	mainFlagSet := flag.NewFlagSet("linna", flag.ExitOnError)
	mainFlagMaker := flags.NewFlagMakerFlagSet(&flags.FlagMakingOptions{
		UseLowerCase: true,
		Flatten:      false,
		TagName:      "yaml",
		TagUsage:     "usage",
	}, mainFlagSet)

	if _, err := mainFlagMaker.ParseArgs(mainConfig, args[1:]); err != nil {
		log.Fatal("Could not parse command line arguments", zap.Error(err))
	}
	return mainConfig
}
