package server

import (
	"fmt"
	"github.com/bio-routing/bio-rd/protocols/bgp/types"
	"io"

	"github.com/bio-routing/bio-rd/util/log"
)

func serializeAndSendUpdate(out io.Writer, update serializeAbleUpdate, opt *types.EncodeOptions) error {
	updateBytes, err := update.SerializeUpdate(opt)
	if err != nil {
		log.Errorf("unable to serialize BGP Update: %v", err)
		return nil
	}

	_, err = out.Write(updateBytes)
	if err != nil {
		return fmt.Errorf("failed sending Update: %w", err)
	}
	return nil
}

type serializeAbleUpdate interface {
	SerializeUpdate(opt *types.EncodeOptions) ([]byte, error)
}
