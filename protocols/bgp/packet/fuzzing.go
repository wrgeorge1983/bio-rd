//go:build go || fuzz
// +build go fuzz

package packet

import (
	"bytes"
	"github.com/bio-routing/bio-rd/util"
)

const (
	INC_PRIO = 1
	KEEP     = 0
	DISMISS  = -1
)

func Fuzz(data []byte) int {
	buf := bytes.NewBuffer(data)
	for _, option := range getAllDecodingOptions() {
		msg, err := Decode(buf, &option)
		if err != nil {
			if msg != nil {
				panic("msg != nil on error")
			}

		}

		return INC_PRIO
	}

	return KEEP
}

func getAllDecodingOptions() []util.DecodeOptions {
	parameters := []bool{true, false}
	var ret []util.DecodeOptions
	for _, octet := range parameters {
		ret = append(ret, util.DecodeOptions{
			Use32BitASN: octet,
		})
	}

	return ret
}
