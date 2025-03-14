package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	bnet "github.com/bio-routing/bio-rd/net"
	"github.com/bio-routing/bio-rd/util/decode"
	"github.com/bio-routing/tflow2/convert"
)

const (
	PathIdentifierLen          = 4
	BytesPerLabel              = 3
	BitsPerLabel               = BytesPerLabel * 8
	BytesPerRouteDistinguisher = 8
	BitsPerRouteDistinguisher  = BytesPerRouteDistinguisher * 8
)

type RouteDistinguisher uint64

func (rd *RouteDistinguisher) serialize(buf *bytes.Buffer) {
	if rd == nil {
		return
	}

	// Convert uint64 to 8 bytes in big-endian order
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(*rd))

	// Write the bytes to the buffer
	buf.Write(b)
}

// NLRI represents a Network Layer Reachability Information
type NLRI struct {
	PathIdentifier     uint32
	RouteDistinguisher *RouteDistinguisher // for VPNv4 and VPNv6 routes
	LabelStack         []LabelStackEntry
	Prefix             *bnet.Prefix
	Next               *NLRI
}

func decodeRouteDistinguisher(buf *bytes.Buffer) (*RouteDistinguisher, error) {
	var rd RouteDistinguisher
	err := decode.Decode(buf, []interface{}{&rd})
	if err != nil {
		return nil, fmt.Errorf("unable to decode route distinguisher: %w", err)
	}
	return &rd, nil
}

func decodeNLRIs(buf *bytes.Buffer, length uint16, afi uint16, safi uint8, addPath bool) (*NLRI, error) {
	var ret *NLRI
	var eol *NLRI
	var nlri *NLRI
	var err error
	var consumed uint8
	p := uint16(0)

	for p < length {
		nlri, consumed, err = decodeNLRI(buf, afi, safi, addPath)
		if err != nil {
			return nil, fmt.Errorf("unable to decode NLRI: %w", err)
		}
		p += uint16(consumed)

		if ret == nil {
			ret = nlri
			eol = nlri
			continue
		}

		eol.Next = nlri
		eol = nlri
	}

	return ret, nil
}

func decodeNLRI(buf *bytes.Buffer, afi uint16, safi uint8, addPath bool) (*NLRI, uint8, error) {
	nlri := &NLRI{}

	consumed := uint8(0)

	if addPath {
		err := decode.Decode(buf, []interface{}{
			&nlri.PathIdentifier,
		})
		if err != nil {
			return nil, consumed, err
		}

		consumed += PathIdentifierLen
	}

	pfxLen, err := buf.ReadByte()
	if err != nil {
		return nil, consumed, err
	}
	consumed++

	if safi == SAFILabeledUnicast || safi == SAFIMPLSVPN {
		nlri.LabelStack = make([]LabelStackEntry, 0, 1)
		for {
			lse, err := decodeLabelStackEntry(buf)
			if err != nil {
				return nil, consumed, fmt.Errorf("decode label stack entry failed: %w", err)
			}

			consumed += BytesPerLabel
			pfxLen -= BitsPerLabel
			nlri.LabelStack = append(nlri.LabelStack, lse)

			if lse.isBottomOfStack() {
				break
			}
		}
	}

	if safi == SAFIMPLSVPN {
		rdValue, err := decodeRouteDistinguisher(buf)
		if err != nil {
			return nil, consumed, fmt.Errorf("decode route distinguisher failed: %w", err)
		}
		consumed += BytesPerRouteDistinguisher
		pfxLen -= BitsPerRouteDistinguisher
		nlri.RouteDistinguisher = rdValue

	}

	numBytes := uint8(BytesInAddr(pfxLen))
	bytes := make([]byte, numBytes)

	r, err := buf.Read(bytes)
	consumed += uint8(r)
	if err != nil {
		return nil, consumed, err
	}
	if r < int(numBytes) {
		return nil, consumed, fmt.Errorf("expected %d bytes for NLRI, only %d remaining", numBytes, r)
	}

	pfx, err := deserializePrefix(bytes, pfxLen, afi)
	if err != nil {
		return nil, consumed, err
	}
	nlri.Prefix = pfx

	return nlri, consumed, nil
}

func (n *NLRI) serialize(buf *bytes.Buffer, addPath bool, safi uint8) uint8 {
	numBytes := uint8(0)

	if addPath {
		buf.Write(convert.Uint32Byte(n.PathIdentifier))
		numBytes += 4
	}

	pfxLen := n.Prefix.Len()
	if safi == SAFILabeledUnicast || safi == SAFIMPLSVPN {
		pfxLen += uint8(len(n.LabelStack) * BitsPerLabel)
	}
	if safi == SAFIMPLSVPN {
		pfxLen += BitsPerRouteDistinguisher
	}

	buf.WriteByte(pfxLen)
	numBytes++

	if safi == SAFILabeledUnicast || safi == SAFIMPLSVPN {
		labelCount := len(n.LabelStack)
		for i, l := range n.LabelStack {
			l.serialize(buf, i == labelCount-1)
			numBytes += BytesPerLabel
		}
	}
	if safi == SAFIMPLSVPN {
		// if n.RouteDistinguisher == nil {
		// 	return 0, fmt.Errorf("cannot serialize VPN route without Route Distinguisher")
		// }
		n.RouteDistinguisher.serialize(buf)
		numBytes += BytesPerRouteDistinguisher
	}

	pfxNumBytes := BytesInAddr(n.Prefix.Len())
	buf.Write(n.Prefix.Addr().Bytes()[:pfxNumBytes])
	numBytes += pfxNumBytes

	return numBytes
}

// BytesInAddr gets the amount of bytes needed to encode an NLRI of prefix length pfxlen
func BytesInAddr(pfxlen uint8) uint8 {
	return uint8(math.Ceil(float64(pfxlen) / 8))
}
