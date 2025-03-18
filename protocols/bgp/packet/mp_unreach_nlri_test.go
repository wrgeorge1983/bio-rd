package packet

import (
	"bytes"
	"testing"

	bnet "github.com/bio-routing/bio-rd/net"
	"github.com/stretchr/testify/assert"
)

func TestSerializeMultiProtocolUnreachNLRI(t *testing.T) {
	tests := []struct {
		name     string
		nlri     MultiProtocolUnreachNLRI
		expected []byte
		addPath  bool
	}{
		{
			name: "Simple IPv6 prefix",
			nlri: MultiProtocolUnreachNLRI{
				AFI:  AFIIPv6,
				SAFI: SAFIUnicast,
				NLRI: &NLRI{
					Prefix: bnet.NewPfx(bnet.IPv6FromBlocks(0x2620, 0x110, 0x9000, 0, 0, 0, 0, 0), 44).Dedup(),
				},
			},
			expected: []byte{
				0x00, 0x02, // AFI
				0x01,                                     // SAFI
				0x2c, 0x26, 0x20, 0x01, 0x10, 0x90, 0x00, // Prefix
			},
		},
		{
			name: "IPv6 prefix with ADD-PATH",
			nlri: MultiProtocolUnreachNLRI{
				AFI:  AFIIPv6,
				SAFI: SAFIUnicast,
				NLRI: &NLRI{
					PathIdentifier: 100,
					Prefix:         bnet.NewPfx(bnet.IPv6FromBlocks(0x2620, 0x110, 0x9000, 0, 0, 0, 0, 0), 44).Dedup(),
				},
			},
			expected: []byte{
				0x00, 0x02, // AFI
				0x01,                  // SAFI
				0x00, 0x00, 0x00, 100, // PathID
				0x2c, 0x26, 0x20, 0x01, 0x10, 0x90, 0x00, // Prefix
			},
			addPath: true,
		},
		{
			name: "VPNv4 Withdraw with RD",
			nlri: MultiProtocolUnreachNLRI{
				AFI:  AFIIPv4,
				SAFI: SAFIVPNUnicast,
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
				0x80,        // SAFI (VPN)
				24 + 64 + 24,     // Prefix Length + RD bits + Label Stack size
				0x49, 0x33, 0x01, // Label (bottom of stack)
				0, 0,             // RD type 0
				0, 100,           // RD Administrator (16-bit value)
				0, 0, 0, 200,     // RD Assigned Number (32-bit value)
				192, 0, 2,        // Prefix
			},
		},
		{
			name: "VPNv6 Withdraw with RD",
			nlri: MultiProtocolUnreachNLRI{
				AFI:  AFIIPv6,
				SAFI: SAFIVPNUnicast,
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
