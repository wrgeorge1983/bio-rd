package packet

import (
	"bytes"
	"testing"

	bnet "github.com/bio-routing/bio-rd/net"
	"github.com/stretchr/testify/assert"
)

func TestSerializeMultiProtocolReachNLRI(t *testing.T) {
	tests := []struct {
		name     string
		nlri     MultiProtocolReachNLRI
		expected []byte
		addPath  bool
	}{
		{
			name: "Simple IPv6 prefix",
			nlri: MultiProtocolReachNLRI{
				AFI:     AFIIPv6,
				SAFI:    SAFIUnicast,
				NextHop: bnet.IPv6FromBlocks(0x2001, 0x678, 0x1e0, 0, 0, 0, 0, 0x2).Dedup(),
				NLRI: &NLRI{
					Prefix: bnet.NewPfx(bnet.IPv6FromBlocks(0x2600, 0x6, 0xff05, 0, 0, 0, 0, 0), 48).Dedup(),
				},
			},
			expected: []byte{
				0x00, 0x02, // AFI
				0x01,                                                                                                 // SAFI
				0x10, 0x20, 0x01, 0x06, 0x78, 0x01, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // NextHop
				0x00,                                     // RESERVED
				0x30, 0x26, 0x00, 0x00, 0x06, 0xff, 0x05, // Prefix
			},
		},
		{
			name: "IPv6 prefix with ADD-PATH",
			nlri: MultiProtocolReachNLRI{
				AFI:     AFIIPv6,
				SAFI:    SAFIUnicast,
				NextHop: bnet.IPv6FromBlocks(0x2001, 0x678, 0x1e0, 0, 0, 0, 0, 0x2).Dedup(),
				NLRI: &NLRI{
					Prefix:         bnet.NewPfx(bnet.IPv6FromBlocks(0x2600, 0x6, 0xff05, 0, 0, 0, 0, 0), 48).Dedup(),
					PathIdentifier: 100,
				},
			},
			expected: []byte{
				0x00, 0x02, // AFI
				0x01,                                                                                                 // SAFI
				0x10, 0x20, 0x01, 0x06, 0x78, 0x01, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // NextHop
				0x00,                  // RESERVED
				0x00, 0x00, 0x00, 100, // PathID
				0x30, 0x26, 0x00, 0x00, 0x06, 0xff, 0x05, // Prefix
			},
			addPath: true,
		},
		{
			name: "IPv4 BGP Labeled Unicast",
			nlri: MultiProtocolReachNLRI{
				AFI:     AFIIPv4,
				SAFI:    SAFILabeledUnicast,
				NextHop: bnet.IPv4FromOctets(192, 0, 2, 0).Dedup(),
				NLRI: &NLRI{
					Prefix: bnet.NewPfx(bnet.IPv4FromOctets(192, 0, 2, 0), 24).Dedup(),
					LabelStack: []LabelStackEntry{
						NewLabelStackEntry(299824),
					},
				},
			},
			expected: []byte{
				0x00, 0x01, // AFI
				0x04,         // SAFI
				0x04,         // NextHop length
				192, 0, 2, 0, // NextHop
				0x00,             // Reserved
				48,               // Prefix Length + Label Stack size (/24 + 24 bytes MPLS)
				0x49, 0x33, 0x01, // Label (bottom of stack)
				192, 0, 2, // Prefix
			},
		},
		{
			name: "VPNv4 with RD",
			nlri: MultiProtocolReachNLRI{
				AFI:     AFIIPv4,
				SAFI:    SAFIVPNUnicast,
				NextHop: bnet.IPv4FromOctets(192, 0, 2, 1).Dedup(),
				NLRI: &NLRI{
					Prefix: bnet.NewPfx(bnet.IPv4FromOctets(192, 0, 2, 0), 24).Dedup(),
					RouteDistinguisher: &RouteDistinguisher{
						Type:           RouteDistinguisherTypeAdministratorSubfield2Octet,
						Administrator:  []byte{0, 100},
						AssignedNumber: []byte{0, 0, 0, 200},
					},
					LabelStack: []LabelStackEntry{
						NewLabelStackEntry(299824),
					},
				},
			},
			expected: []byte{
				0x00, 0x01, // AFI
				0x80,         // SAFI (VPN)
				0x04,         // NextHop length
				192, 0, 2, 1, // NextHop
				0x00,             // Reserved
				24 + 64 + 24,     // Prefix Length + RD bits + Label Stack size
				0x49, 0x33, 0x01, // Label (bottom of stack)
				0, 0,             // RD type 0
				0, 100,           // RD Administrator (16-bit value)
				0, 0, 0, 200,     // RD Assigned Number (32-bit value)
				192, 0, 2,        // Prefix
			},
		},
		{
			name: "VPNv6 with RD",
			nlri: MultiProtocolReachNLRI{
				AFI:     AFIIPv6,
				SAFI:    SAFIVPNUnicast,
				NextHop: bnet.IPv6FromBlocks(0x2001, 0x678, 0x1e0, 0, 0, 0, 0, 0x2).Dedup(),
				NLRI: &NLRI{
					Prefix: bnet.NewPfx(bnet.IPv6FromBlocks(0x2600, 0x6, 0xff05, 0, 0, 0, 0, 0), 48).Dedup(),
					RouteDistinguisher: &RouteDistinguisher{
						Type:           RouteDistinguisherTypeAdministratorSubfield4Octet,
						Administrator:  []byte{0, 0, 0, 100},
						AssignedNumber: []byte{0, 200},
					},
					LabelStack: []LabelStackEntry{
						NewLabelStackEntry(299824),
					},
				},
			},
			expected: []byte{
				0x00, 0x02, // AFI (IPv6)
				0x80,        // SAFI (VPN)
				0x10,        // NextHop length (16 bytes)
				0x20, 0x01, 0x06, 0x78, 0x01, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // NextHop
				0x00,             // Reserved
				48 + 64 + 24,     // Prefix Length + RD bits + Label Stack size
				0x49, 0x33, 0x01, // Label (bottom of stack)
				0, 1,             // RD type 1
				0, 0, 0, 100,     // RD Administrator (32-bit ASN)
				0, 200,           // RD Assigned Number (16-bit value)
				0x26, 0x00, 0x00, 0x06, 0xff, 0x05, // Prefix (2600:6:ff05::/48)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			test.nlri.serialize(buf, &EncodeOptions{
				UseAddPath: test.addPath,
			})
			assert.Equal(t, test.expected, buf.Bytes())
		})
	}
}
