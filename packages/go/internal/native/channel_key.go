package native

import (
	"sync"

	"github.com/ebitengine/purego"
)

type deriveChannelKeyResult struct {
	Error    DeRecError
	KeyBytes DeRecBuffer
}

var (
	deriveChannelKeyOnce sync.Once
	deriveChannelKeyFn   func(key *byte, keyLen uintptr, epoch, toEpoch uint32) deriveChannelKeyResult
)

func DeriveChannelKey(key []byte, epoch, toEpoch uint32) ([]byte, error) {
	deriveChannelKeyOnce.Do(func() {
		purego.RegisterFunc(&deriveChannelKeyFn, symbol("derive_channel_key"))
	})
	res := deriveChannelKeyFn(bytePtr(key), uintptr(len(key)), epoch, toEpoch)
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.KeyBytes), nil
}
