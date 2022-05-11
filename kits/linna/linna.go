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
// Author: randyma 435420057@qq.com
// Date: 2022-05-09 09:53:57
// LastEditors: randyma 435420057@qq.com
// LastEditTime: 2022-05-09 10:58:47
// FilePath: \linna\kits\linna\linna.go
// Description:
package linna

import (
	"flag"
	"fmt"
	"os"
)

// ParseArgs 参数解析
func ParseArgs(v, commitid, buildAt string) string {
	if len(os.Args) < 1 {
		return ""
	}

	var (
		// fp 配置文件地址
		fp string

		// showVersion 显示版本信息
		showVersion bool

		// showHelp 显示配置信息
		showHelp bool
	)

	fs := flag.NewFlagSet("linna", flag.ExitOnError)
	fs.Usage = usage
	fs.BoolVar(&showVersion, "version", false, "Print version information")
	fs.BoolVar(&showVersion, "v", false, "Print version information")
	fs.StringVar(&fp, "c", "", "Configuration file")
	fs.StringVar(&fp, "config", "", "Configuration file")
	fs.BoolVar(&showHelp, "h", false, "Show help message.")
	fs.BoolVar(&showHelp, "help", false, "Show help message.")
	fs.Parse(os.Args[1:])
	if showHelp {
		usage()
	}

	if showVersion {
		fmt.Printf("%s + %s + %s\n", v, commitid, buildAt)
		os.Exit(0)
	}

	return fp
}

var usageStr = `
Usage: linna [options]
    -c, --config                     Configuration file
    -h, --help                       Show help message
    -v, --version                    Show version
`

func usage() {
	fmt.Printf("%s\n", usageStr)
	os.Exit(0)
}

// Serve 开启linna服务
func Serve() error {
	return nil
}
