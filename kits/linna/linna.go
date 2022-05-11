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
	"io/ioutil"
	"os"

	"go.uber.org/zap"
	yaml "gopkg.in/yaml.v3"
)

var usageStr = `
Usage: linna [options]
    -c, --config                     配置文件地址
    -h, --help                       显示帮助信息
    -v, --version                    显示版本信息
`

// ParseArgs 参数解析
func ParseArgs(log *zap.Logger, v, commitid, buildAt string) Configuration {
	if len(os.Args) < 1 {
		return NewConfiguration()
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
	fs.BoolVar(&showVersion, "version", false, "版本信息")
	fs.BoolVar(&showVersion, "v", false, "版本信息")
	fs.StringVar(&fp, "c", "", "配置文件地址")
	fs.StringVar(&fp, "config", "", "配置文件地址")
	fs.BoolVar(&showHelp, "h", false, "显示帮助信息")
	fs.BoolVar(&showHelp, "help", false, "显示帮助信息")
	fs.Parse(os.Args[1:])
	if showHelp {
		usage()
	}

	if showVersion {
		fmt.Printf("%s + %s + %s\n", v, commitid, buildAt)
		os.Exit(0)
	}

	// 解析配置文件
	if len(fp) == 0 {
		log.Panic("配置文件地址不正确")
	}

	// 读取配置文件
	if _, err := os.Stat(fp); os.IsNotExist(err) {
		log.Panic("读取配置文件错误", zap.String("error", err.Error()))
	}

	f, err := os.Open(fp)
	if err != nil {
		log.Panic("读取配置文件错误", zap.String("error", err.Error()))
	}

	defer f.Close()
	data, err := ioutil.ReadAll(f)
	if err != nil {
		log.Panic("读取配置文件错误", zap.String("error", err.Error()))
	}

	config := NewConfiguration()
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Panic("解析配置文件出错", zap.String("error", err.Error()))
	}

	config.SourceFile = fp
	return config
}

func usage() {
	fmt.Printf("%s\n", usageStr)
	os.Exit(0)
}

// Serve 开启linna服务
func Serve(config Configuration) error {

	return nil
}

func Shutdown() {
}

func Reload(config Configuration) error {
	return nil
}
