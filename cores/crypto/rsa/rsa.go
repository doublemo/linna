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
// Date: 2022-05-31 23:45:26
// LastEditors: Randyma
// LastEditTime: 2022-05-31 23:45:46
// Description: RAS加密

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

func ReadPEM(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer f.Close()
	return ioutil.ReadAll(f)
}

func Encrypt(data []byte, pub string) ([]byte, error) {
	pubkey, err := ReadPEM(pub)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pubkey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return rsa.EncryptPKCS1v15(rand.Reader, pubInterface.(*rsa.PublicKey), data)
}

func Decrypt(data []byte, privkey string) ([]byte, error) {
	pkey, err := ReadPEM(privkey)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pkey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, data)
}
