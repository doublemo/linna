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
// Date: 2022-05-31 23:47:33
// LastEditors: Randyma
// LastEditTime: 2022-05-31 23:47:54
// Description:

package xxtea

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func Test_XXTEA(t *testing.T) {
	str := "Hello World! 你好，中国！asdaczvhgjzxc!@#$%^&*()_+[]{}|:<>?;',./"
	key := "1234567890"
	encrypt_data := Encrypt([]byte(str), []byte(key))
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt_data))

	//Test format between
	url_str := EncryptStdToURLString(str, key)
	fmt.Println(url_str)
	std_str, _ := DecryptURLToStdString(url_str, key)
	fmt.Println(std_str)

	decrypt_data := string(Decrypt(encrypt_data, []byte(key)))
	if str != decrypt_data {
		t.Error(str)
		t.Error(decrypt_data)
		t.Error("fail!")
	}

	if std_str != str {
	}

}
