package mplri

import (
	"bytes"
	"fmt"
	"github.com/bio-routing/bio-rd/net"
	"github.com/bio-routing/bio-rd/protocols/bgp/types"
	"github.com/bio-routing/bio-rd/util"
	"github.com/bio-routing/bio-rd/util/decode"
	"github.com/bio-routing/tflow2/convert"
)

// MultiProtocolReachNLRI represents network layer reachability information for an IP address family (rfc4760)
type MultiProtocolReachNLRI struct {
	AFI     uint16
	SAFI    uint8
	NextHop *net.IP
	NLRI    *NLRI
}

func (n *MultiProtocolReachNLRI) Serialize(buf *bytes.Buffer, opt *types.EncodeOptions) uint16 {
	nextHop := n.NextHop.Bytes()

	tempBuf := bytes.NewBuffer(nil)
	tempBuf.Write(convert.Uint16Byte(n.AFI))
	tempBuf.WriteByte(n.SAFI)
	tempBuf.WriteByte(uint8(len(nextHop)))
	tempBuf.Write(nextHop)
	tempBuf.WriteByte(0) // RESERVED

	for cur := n.NLRI; cur != nil; cur = cur.Next {
		cur.Serialize(tempBuf, opt.UseAddPath, n.SAFI)
	}

	buf.Write(tempBuf.Bytes())

	return uint16(tempBuf.Len())
}

func DeserializeMultiProtocolReachNLRI(b []byte, opt *util.DecodeOptions) (MultiProtocolReachNLRI, error) {
	n := MultiProtocolReachNLRI{}
	nextHopLength := uint8(0)

	variableLength := len(b) - 4 // 4 <- AFI + SAFI + NextHopLength
	if variableLength <= 0 {
		return n, fmt.Errorf("invalid length of MP_REACH_NLRI: expected more than 4 bytes but got %d", len(b))
	}

	variable := make([]byte, variableLength)
	fields := []interface{}{
		&n.AFI,
		&n.SAFI,
		&nextHopLength,
		&variable,
	}
	err := decode.Decode(bytes.NewBuffer(b), fields)
	if err != nil {
		return MultiProtocolReachNLRI{}, err
	}

	budget := variableLength
	if budget < int(nextHopLength) {
		return MultiProtocolReachNLRI{},
			fmt.Errorf("failed to decode next hop IP: expected %d bytes for NLRI, only %d remaining", nextHopLength, budget)
	}

	firstNextHopLength := nextHopLength
	if nextHopLength == 32 {
		// second next-hop is lladdr (see rfc2545 sec 3 par 2)
		firstNextHopLength = 16
	}
	nh, err := net.IPFromBytes(variable[:firstNextHopLength])
	if err != nil {
		return MultiProtocolReachNLRI{}, fmt.Errorf("failed to decode next hop IP: %w", err)
	}
	n.NextHop = nh.Dedup()
	budget -= int(nextHopLength)

	if budget == 0 {
		return n, nil
	}

	variable = variable[1+nextHopLength:] // 1 <- RESERVED field

	buf := bytes.NewBuffer(variable)
	nlri, err := DecodeNLRIs(buf, uint16(buf.Len()), n.AFI, n.SAFI, opt.AddPath(n.AFI, n.SAFI))
	if err != nil {
		return MultiProtocolReachNLRI{}, err
	}
	n.NLRI = nlri

	return n, nil
}
