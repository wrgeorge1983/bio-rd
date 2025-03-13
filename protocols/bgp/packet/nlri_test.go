package packet

import (
	"bytes"
	"testing"

	bnet "github.com/bio-routing/bio-rd/net"
	"github.com/stretchr/testify/assert"
)

func TestDecodeNLRIs(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		wantFail bool
		expected *NLRI
	}{
		{
			name: "Valid NRLI #1",
			input: []byte{
				24, 192, 168, 0,
				8, 10,
				17, 172, 16, 0,
			},
			wantFail: false,
			expected: &NLRI{
				Prefix: bnet.NewPfx(bnet.IPv4FromOctets(192, 168, 0, 0), 24).Dedup(),
				Next: &NLRI{
					Prefix: bnet.NewPfx(bnet.IPv4FromOctets(10, 0, 0, 0), 8).Dedup(),
					Next: &NLRI{
						Prefix: bnet.NewPfx(bnet.IPv4FromOctets(172, 16, 0, 0), 17).Dedup(),
					},
				},
			},
		},
		{
			name: "Invalid NRLI #1",
			input: []byte{
				24, 192, 168, 0,
				8, 10,
				17, 172, 16,
			},
			wantFail: true,
		},
	}

	for _, test := range tests {
		buf := bytes.NewBuffer(test.input)
		res, err := decodeNLRIs(buf, uint16(len(test.input)), AFIIPv4, SAFIUnicast, false)

		if test.wantFail && err == nil {
			t.Errorf("Expected error did not happen for test %q", test.name)
		}

		if !test.wantFail && err != nil {
			t.Errorf("Unexpected failure for test %q: %v", test.name, err)
		}

		assert.Equal(t, test.expected, res)
	}
}

func TestDecodeNLRIv6(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		addPath  bool
		wantFail bool
		expected *NLRI
	}{
		{
			name: "IPv6 default",
			input: []byte{
				0,
			},
			wantFail: false,
			expected: &NLRI{
				Prefix: bnet.NewPfx(bnet.IPv6FromBlocks(0, 0, 0, 0, 0, 0, 0, 0), 0).Dedup(),
			},
		},
	}

	for _, test := range tests {
		buf := bytes.NewBuffer(test.input)
		res, _, err := decodeNLRI(buf, AFIIPv6, SAFIUnicast, test.addPath)

		if test.wantFail && err == nil {
			t.Errorf("Expected error did not happen for test %q", test.name)
		}

		if !test.wantFail && err != nil {
			t.Errorf("Unexpected failure for test %q: %v", test.name, err)
		}

		assert.Equal(t, test.expected, res)
	}
}

func TestDecodeNLRI(t *testing.T) {
	tests := []struct {
		name     string
		safi     uint8
		input    []byte
		addPath  bool
		wantFail bool
		expected *NLRI
	}{
		{
			name: "LU NLRI #1",
			safi: SAFILabeledUnicast,
			input: []byte{
				42,               // prefix + label stack length
				0x49, 0x33, 0x01, // MPLS label
				5, 193, 0, 0, // 5.193.0.0/18 (42 - 24 = 18)
			},
			wantFail: false,
			expected: &NLRI{
				LabelStack: []LabelStackEntry{
					0x00493301,
				},
				Prefix: bnet.NewPfx(bnet.IPv4FromOctets(5, 193, 0, 0), 18).Dedup(),
			},
		},
		{
			name: "LU NLRI #2",
			safi: SAFILabeledUnicast,
			input: []byte{
				66,               // prefix + label stack length
				0x49, 0x33, 0x00, // MPLS label
				0x49, 0x33, 0x01, // MPLS label
				5, 193, 0, 0, // 5.193.0.0/18 (66 - 48 = 18)
			},
			wantFail: false,
			expected: &NLRI{
				LabelStack: []LabelStackEntry{
					0x00493300,
					0x00493301,
				},
				Prefix: bnet.NewPfx(bnet.IPv4FromOctets(5, 193, 0, 0), 18).Dedup(),
			},
		},
		{
			name: "Valid NRLI #1",
			input: []byte{
				24, 192, 168, 0,
			},
			wantFail: false,
			expected: &NLRI{
				Prefix: bnet.NewPfx(bnet.IPv4FromOctets(192, 168, 0, 0), 24).Dedup(),
			},
		},
		{
			name: "Valid NRLI #2",
			input: []byte{
				25, 192, 168, 0, 128,
			},
			wantFail: false,
			expected: &NLRI{
				Prefix: bnet.NewPfx(bnet.IPv4FromOctets(192, 168, 0, 128), 25).Dedup(),
			},
		},
		{
			name: "Incomplete NLRI #1",
			input: []byte{
				25, 192, 168, 0,
			},
			wantFail: true,
		},
		{
			name: "Incomplete NLRI #2",
			input: []byte{
				25,
			},
			wantFail: true,
		},

		{
			name: "Valid NRLI #1 add path",
			input: []byte{
				0, 0, 0, 10, 24, 192, 168, 0,
			},
			addPath:  true,
			wantFail: false,
			expected: &NLRI{
				PathIdentifier: 10,
				Prefix:         bnet.NewPfx(bnet.IPv4FromOctets(192, 168, 0, 0), 24).Dedup(),
			},
		},
		{
			name: "Valid NRLI #2 add path",
			input: []byte{
				0, 0, 1, 0, 25, 192, 168, 0, 128,
			},
			addPath:  true,
			wantFail: false,
			expected: &NLRI{
				PathIdentifier: 256,
				Prefix:         bnet.NewPfx(bnet.IPv4FromOctets(192, 168, 0, 128), 25).Dedup(),
			},
		},
		{
			name: "Incomplete path Identifier",
			input: []byte{
				0, 0, 0,
			},
			addPath:  true,
			wantFail: true,
		},
		{
			name: "Incomplete NLRI #1  add path",
			input: []byte{
				0, 0, 1, 0, 25, 192, 168, 0,
			},
			addPath:  true,
			wantFail: true,
		},
		{
			name: "Incomplete NLRI #2  add path",
			input: []byte{
				0, 0, 1, 0, 25,
			},
			addPath:  true,
			wantFail: true,
		},
		{
			name:     "Empty input",
			input:    []byte{},
			wantFail: true,
		},
		{
			name: "VPNv4 NLRI",
			safi: SAFIMPLSVPN,
			input: []byte{
				112,               // prefix + label stack + RD length
				0x49, 0x33, 0x01, // MPLS label with bottom bit set
				0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, // Route Distinguisher (8 bytes)
				192, 168, 1,      // Prefix: 192.168.1.0/24
			},
			wantFail: false,
			expected: &NLRI{
				LabelStack: []LabelStackEntry{
					0x00493301,
				},
				RouteDistinguisher: func() *RouteDistinguisher {
					rd := RouteDistinguisher(0x0001000000010001)
					return &rd
				}(),
				Prefix: bnet.NewPfx(bnet.IPv4FromOctets(192, 168, 1, 0), 24).Dedup(),
			},
		},
		{
			name: "VPNv4 NLRI with multiple labels",
			safi: SAFIMPLSVPN,
			input: []byte{
				130,              // prefix + label stack + RD length
				0x49, 0x33, 0x00, // MPLS label 1
				0x49, 0x34, 0x01, // MPLS label 2 with bottom bit set
				0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, // Route Distinguisher (8 bytes)
				10, 0, 0,         // Prefix: 10.0.0.0/18
			},
			wantFail: false,
			expected: &NLRI{
				LabelStack: []LabelStackEntry{
					0x00493300,
					0x00493401,
				},
				RouteDistinguisher: func() *RouteDistinguisher {
					rd := RouteDistinguisher(0x0002000000030004)
					return &rd
				}(),
				Prefix: bnet.NewPfx(bnet.IPv4FromOctets(10, 0, 0, 0), 18).Dedup(),
			},
		},
		{
			name: "Incomplete VPNv4 NLRI (missing RD bytes)",
			safi: SAFIMPLSVPN,
			input: []byte{
				80,               // prefix + label stack + RD length
				0x49, 0x33, 0x01, // MPLS label with bottom bit set
				0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // Incomplete RD (only 6 bytes)
			},
			wantFail: true,
		},
	}

	for _, test := range tests {
		buf := bytes.NewBuffer(test.input)
		res, _, err := decodeNLRI(buf, AFIIPv4, test.safi, test.addPath)

		if test.wantFail && err == nil {
			t.Errorf("Expected error did not happen for test %q", test.name)
		}

		if !test.wantFail && err != nil {
			t.Errorf("Unexpected failure for test %q: %v", test.name, err)
		}

		assert.Equal(t, test.expected, res, test.name)
	}
}

func TestBytesInAddr(t *testing.T) {
	tests := []struct {
		name     string
		input    uint8
		expected uint8
	}{
		{
			name:     "Test #1",
			input:    24,
			expected: 3,
		},
		{
			name:     "Test #2",
			input:    25,
			expected: 4,
		},
		{
			name:     "Test #3",
			input:    32,
			expected: 4,
		},
		{
			name:     "Test #4",
			input:    0,
			expected: 0,
		},
		{
			name:     "Test #5",
			input:    9,
			expected: 2,
		},
	}

	for _, test := range tests {
		res := BytesInAddr(test.input)
		if res != test.expected {
			t.Errorf("Unexpected result for test %q: %d", test.name, res)
		}
	}
}

func TestNLRISerialize(t *testing.T) {
	tests := []struct {
		name     string
		nlri     *NLRI
		addPath  bool
		safi     uint8
		expected []byte
	}{
		{
			name: "Test #1",
			nlri: &NLRI{
				Prefix: bnet.NewPfx(bnet.IPv4FromOctets(1, 2, 3, 0), 25).Dedup(),
			},
			safi:     SAFIUnicast,
			expected: []byte{25, 1, 2, 3, 0},
		},
		{
			name: "Test #2",
			nlri: &NLRI{
				Prefix: bnet.NewPfx(bnet.IPv4FromOctets(1, 2, 3, 0), 24).Dedup(),
			},
			safi:     SAFIUnicast,
			expected: []byte{24, 1, 2, 3},
		},
		{
			name: "Test #3",
			nlri: &NLRI{
				Prefix: bnet.NewPfx(bnet.IPv4FromOctets(100, 200, 128, 0), 17).Dedup(),
			},
			safi:     SAFIUnicast,
			expected: []byte{17, 100, 200, 128},
		},
		{
			name: "with add-path #1",
			nlri: &NLRI{
				PathIdentifier: 100,
				Prefix:         bnet.NewPfx(bnet.IPv4FromOctets(1, 2, 3, 0), 25).Dedup(),
			},
			addPath:  true,
			safi:     SAFIUnicast,
			expected: []byte{0, 0, 0, 100, 25, 1, 2, 3, 0},
		},
		{
			name: "with add-path #2",
			nlri: &NLRI{
				PathIdentifier: 100,
				Prefix:         bnet.NewPfx(bnet.IPv4FromOctets(1, 2, 3, 0), 24).Dedup(),
			},
			addPath:  true,
			safi:     SAFIUnicast,
			expected: []byte{0, 0, 0, 100, 24, 1, 2, 3},
		},
		{
			name: "with add-path #3",
			nlri: &NLRI{
				PathIdentifier: 100,
				Prefix:         bnet.NewPfx(bnet.IPv4FromOctets(100, 200, 128, 0), 17).Dedup(),
			},
			addPath:  true,
			safi:     SAFIUnicast,
			expected: []byte{0, 0, 0, 100, 17, 100, 200, 128},
		},
		{
			name: "BGP-LU single label",
			nlri: &NLRI{
				Prefix: bnet.NewPfx(bnet.IPv4FromOctets(100, 200, 128, 0), 17).Dedup(),
				LabelStack: []LabelStackEntry{
					NewLabelStackEntry(299824),
				},
			},
			safi:     SAFILabeledUnicast,
			expected: []byte{17 + 24, 0x49, 0x33, 0x01, 100, 200, 128},
		},
		{
			name: "BGP-LU multi label",
			nlri: &NLRI{
				Prefix: bnet.NewPfx(bnet.IPv4FromOctets(100, 200, 128, 0), 17).Dedup(),
				LabelStack: []LabelStackEntry{
					NewLabelStackEntry(299824),
					NewLabelStackEntry(299841),
				},
			},
			safi:     SAFILabeledUnicast,
			expected: []byte{17 + 24 + 24, 0x49, 0x33, 0x00, 0x49, 0x34, 0x11, 100, 200, 128},
		},
		{
			name: "VPNv4 NLRI",
			nlri: &NLRI{
				Prefix: bnet.NewPfx(bnet.IPv4FromOctets(192, 168, 1, 0), 24).Dedup(),
				LabelStack: []LabelStackEntry{
					NewLabelStackEntry(299824),
				},
				RouteDistinguisher: func() *RouteDistinguisher {
					rd := RouteDistinguisher(0x0001000000010001)
					return &rd
				}(),
			},
			safi:     SAFIMPLSVPN,
			expected: []byte{112, 0x49, 0x33, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 192, 168, 1},
		},
		{
			name: "VPNv4 NLRI with multiple labels",
			nlri: &NLRI{
				Prefix: bnet.NewPfx(bnet.IPv4FromOctets(10, 0, 0, 0), 24).Dedup(),
				LabelStack: []LabelStackEntry{
					NewLabelStackEntry(299824),
					NewLabelStackEntry(299841),
				},
				RouteDistinguisher: func() *RouteDistinguisher {
					rd := RouteDistinguisher(0x0002000000030004)
					return &rd
				}(),
			},
			safi:     SAFIMPLSVPN,
			expected: []byte{136, 0x49, 0x33, 0x00, 0x49, 0x34, 0x11, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 10, 0, 0},
		},
		{
			name: "VPNv4 NLRI with add-path",
			nlri: &NLRI{
				PathIdentifier: 42,
				Prefix: bnet.NewPfx(bnet.IPv4FromOctets(192, 168, 1, 0), 24).Dedup(),
				LabelStack: []LabelStackEntry{
					NewLabelStackEntry(299824),
				},
				RouteDistinguisher: func() *RouteDistinguisher {
					rd := RouteDistinguisher(0x0001000000010001)
					return &rd
				}(),
			},
			addPath:  true,
			safi:     SAFIMPLSVPN,
			expected: []byte{0, 0, 0, 42, 112, 0x49, 0x33, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 192, 168, 1},
		},
	}

	for _, test := range tests {
		buf := bytes.NewBuffer(nil)
		test.nlri.serialize(buf, test.addPath, test.safi)
		res := buf.Bytes()
		assert.Equal(t, test.expected, res, test.name)
	}
}
