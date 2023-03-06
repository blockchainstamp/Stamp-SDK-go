package com

import (
	"errors"
	"github.com/btcsuite/btcutil/base58"
	"strings"
)

type Address string

const (
	AccPrefix = "BS"
	AccLen    = 20
)

var (
	InvalidAddr = errors.New("invalid address")
)

func PubToAddr(key []byte) (Address, string) {
	codedKey := base58.Encode(key)
	var addr, suffix = "", ""
	if len(codedKey) > AccLen {
		addr = string([]byte(codedKey)[:AccLen])
		suffix = string([]byte(codedKey)[AccLen:])
	}
	return Address(AccPrefix + addr), suffix
}

func RecoverPub(addr Address, suffix string) ([]byte, error) {
	if len(addr) < AccLen {
		return nil, InvalidAddr
	}
	source := strings.TrimPrefix(string(addr), AccPrefix)
	prefix := base58.Decode(source + suffix)
	return prefix, nil
}
