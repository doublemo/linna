package id

import (
	"encoding/base64"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/xtea"
)

// Encrypt 加密ID key 长度必须为16byte
func Encrypt(uid uint64, key []byte) (string, error) {
	cipher, err := xtea.NewCipher(key)
	if err != nil {
		return "", err
	}

	var src = make([]byte, 8)
	var dst = make([]byte, 8)
	binary.LittleEndian.PutUint64(src, uid)
	cipher.Encrypt(dst, src)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(dst), nil
}

// Decrypt 解密
func Decrypt(uid string, key []byte) (uint64, error) {
	m, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(uid)
	if err != nil {
		return 0, err
	}

	if len(m) < 8 {
		return 0, errors.New("invalid data size")
	}

	cipher, err := xtea.NewCipher(key)
	if err != nil {
		return 0, err
	}

	var dst = make([]byte, 8)
	cipher.Decrypt(dst, m)
	binary.LittleEndian.Uint64(dst)
	return binary.LittleEndian.Uint64(dst), nil
}
