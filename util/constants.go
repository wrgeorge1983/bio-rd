package util

// AFName returns the name of an address family
func AFName(afi uint16, safi uint8) string {
	switch safi {
	case SAFIUnicast:
		switch afi {
		case AFIIPv4:
			return "IPv4"
		case AFIIPv6:
			return "IPv6"
		}
	case SAFIMPLSVPN:
		switch afi {
		case AFIIPv4:
			return "VPNv4"
		case AFIIPv6:
			return "VPNv6"
		}
	case SAFILabeledUnicast:
		switch afi {
		case AFIIPv4:
			return "IPv4LU"
		case AFIIPv6:
			return "IPv6LU"
		}
	}
	return "Unknown AFI/SAFI"
}

const AFIIPv4 = 1

const AFIIPv6 = 2

const SAFIUnicast = 1

const SAFILabeledUnicast = 4

const SAFIMPLSVPN = 128

var (
	AfiAddrLenBytes = map[uint16]uint8{
		1: 4,
		2: 16,
	}
)

// DecodeOptions represents options for the BGP message decoder
type DecodeOptions struct {
	AddPathIPv4Unicast bool
	AddPathIPv6Unicast bool
	Use32BitASN        bool
}

func (d *DecodeOptions) AddPath(afi uint16, safi uint8) bool {
	switch afi {
	case AFIIPv4:
		switch safi {
		case SAFIUnicast:
			return d.AddPathIPv4Unicast
		}
	case AFIIPv6:
		switch safi {
		case SAFIUnicast:
			return d.AddPathIPv6Unicast
		}
	}

	return false
}
