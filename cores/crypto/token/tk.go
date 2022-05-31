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
// Date: 2022-05-31 23:49:06
// LastEditors: Randyma
// LastEditTime: 2022-05-31 23:49:22
// Description:

package token

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"

	"github.com/doublemo/linna/cores/crypto/aes"
)

type TK struct {
	key []byte
}

func (tk *TK) Encrypt(data interface{}) (string, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, data); err != nil {
		return "", err
	}

	hasher := hmac.New(sha256.New, tk.key)
	if _, err := hasher.Write(buf.Bytes()); err != nil {
		return "", err
	}

	if err := binary.Write(buf, binary.LittleEndian, hasher.Sum(nil)); err != nil {
		return "", err
	}

	frame, err := aes.Encrypt(buf.Bytes(), tk.key)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(frame), nil
}

func (tk *TK) Decrypt(s string, o interface{}) error {
	data, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(s)
	if err != nil {
		return err
	}

	dataSize := binary.Size(o)
	if len(data) < dataSize+sha256.Size {
		return errors.New("Token is too short")
	}

	data, err = aes.Decrypt(data, tk.key)
	if err != nil {
		return err
	}

	buf := bytes.NewBuffer(data)
	if err := binary.Read(buf, binary.LittleEndian, o); err != nil {
		return err
	}

	hbuf := new(bytes.Buffer)
	binary.Write(hbuf, binary.LittleEndian, o)

	hasher := hmac.New(sha256.New, tk.key)
	hasher.Write(hbuf.Bytes())

	if !hmac.Equal(data[dataSize:dataSize+sha256.Size], hasher.Sum(nil)) {
		return errors.New("ErrFailed")
	}

	return nil
}

func NewTK(k []byte) *TK {
	return &TK{key: k}
}
