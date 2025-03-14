package util

import (
	"fmt"
	"github.com/bio-routing/bio-rd/net"
)

func DeserializePrefix(b []byte, pfxLen uint8, afi uint16) (*net.Prefix, error) {
	numBytes := BytesInAddr(pfxLen)

	if numBytes != uint8(len(b)) {
		return nil, fmt.Errorf("could not parse prefix of length %d. Expected %d bytes, got %d", pfxLen, numBytes, len(b))
	}

	if afi == AFIIPv4 {
		return net.NewPfx(net.IPv4FromBytes(b), pfxLen).Dedup(), nil
	}

	ipBytes := make([]byte, AfiAddrLenBytes[afi])
	copy(ipBytes, b)

	ip, err := net.IPFromBytes(ipBytes)
	if err != nil {
		return nil, err
	}

	pfx := net.NewPfx(ip, pfxLen)
	if !pfx.Valid() {
		return nil, fmt.Errorf("invalid prefix: %q", pfx.String())
	}

	return pfx.Dedup(), nil
}
