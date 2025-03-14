package mplri

import (
	"bytes"
	"fmt"
	"github.com/bio-routing/bio-rd/protocols/bgp/types"
	"github.com/bio-routing/bio-rd/util"

	"github.com/bio-routing/bio-rd/util/decode"
	"github.com/bio-routing/tflow2/convert"
)

// MultiProtocolUnreachNLRI represents network layer withdraw information for one prefix of an IP address family (rfc4760)
type MultiProtocolUnreachNLRI struct {
	AFI  uint16
	SAFI uint8
	NLRI *NLRI
}

func (n *MultiProtocolUnreachNLRI) Serialize(buf *bytes.Buffer, opt *types.EncodeOptions) uint16 {
	tempBuf := bytes.NewBuffer(nil)
	tempBuf.Write(convert.Uint16Byte(n.AFI))
	tempBuf.WriteByte(n.SAFI)

	for cur := n.NLRI; cur != nil; cur = cur.Next {
		cur.Serialize(tempBuf, opt.UseAddPath, n.SAFI)
	}

	buf.Write(tempBuf.Bytes())

	return uint16(tempBuf.Len())
}

func DeserializeMultiProtocolUnreachNLRI(b []byte, opt *util.DecodeOptions) (MultiProtocolUnreachNLRI, error) {
	n := MultiProtocolUnreachNLRI{}

	prefixesLength := len(b) - 3 // 3 <- AFI + SAFI
	if prefixesLength < 0 {
		return n, fmt.Errorf("invalid length of MP_UNREACH_NLRI: expected more than 3 bytes but got %d", len(b))
	}

	nlris := make([]byte, prefixesLength)
	fields := []interface{}{
		&n.AFI,
		&n.SAFI,
		&nlris,
	}
	err := decode.Decode(bytes.NewBuffer(b), fields)
	if err != nil {
		return MultiProtocolUnreachNLRI{}, err
	}

	if len(nlris) == 0 {
		return n, nil
	}

	buf := bytes.NewBuffer(nlris)
	nlri, err := DecodeNLRIs(buf, uint16(buf.Len()), n.AFI, n.SAFI, opt.AddPath(n.AFI, n.SAFI))
	if err != nil {
		return MultiProtocolUnreachNLRI{}, err
	}
	n.NLRI = nlri

	return n, nil
}
