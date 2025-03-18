package packet

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRouteDistinguisherSerialization(t *testing.T) {
	tests := []struct {
		name string
		rd   *RouteDistinguisher
	}{
		{
			name: "RD type 0",
			rd: &RouteDistinguisher{
				Type:           RouteDistinguisherTypeAdministratorSubfield2Octet,
				Administrator:  []byte{0x00, 0x01},
				AssignedNumber: []byte{0x00, 0x00, 0x00, 0x02},
			},
		},
		{
			name: "RD type 1",
			rd: &RouteDistinguisher{
				Type:           RouteDistinguisherTypeAdministratorSubfield4Octet,
				Administrator:  []byte{0x00, 0x00, 0x00, 0x01},
				AssignedNumber: []byte{0x00, 0x02},
			},
		},
		{
			name: "RD type 2",
			rd: &RouteDistinguisher{
				Type:           RouteDistinguisherTypeAdministratorSubfield4OctetIP,
				Administrator:  []byte{192, 168, 0, 1},
				AssignedNumber: []byte{0x00, 0x02},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf := bytes.NewBuffer(nil)
			test.rd.Serialize(buf)

			rdBytes := buf.Bytes()
			assert.Equal(t, RouteDistinguisherLength, len(rdBytes))

			rd, err := deserializeRouteDistinguisher(rdBytes)
			assert.NoError(t, err)
			assert.Equal(t, test.rd.Type, rd.Type)
			assert.Equal(t, test.rd.Administrator, rd.Administrator)
			assert.Equal(t, test.rd.AssignedNumber, rd.AssignedNumber)
		})
	}
}

func TestRouteDistinguisherParsing(t *testing.T) {
	tests := []struct {
		name           string
		rdStr          string
		expectedType   uint16
		expectedAdmin  string
		expectedAssign string
		expectError    bool
	}{
		{
			name:           "Type 0 RD",
			rdStr:          "100:200",
			expectedType:   RouteDistinguisherTypeAdministratorSubfield2Octet,
			expectedAdmin:  "100",
			expectedAssign: "200",
		},
		{
			name:           "Type 1 RD",
			rdStr:          "123456:789",
			expectedType:   RouteDistinguisherTypeAdministratorSubfield4Octet,
			expectedAdmin:  "123456",
			expectedAssign: "789",
		},
		{
			name:           "Type 2 RD",
			rdStr:          "192.168.1.1:1000",
			expectedType:   RouteDistinguisherTypeAdministratorSubfield4OctetIP,
			expectedAdmin:  "192.168.1.1",
			expectedAssign: "1000",
		},
		{
			name:        "Invalid format",
			rdStr:       "invalid",
			expectError: true,
		},
		{
			name:        "Invalid IP",
			rdStr:       "256.0.0.1:100",
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rd, err := ParseRouteDistinguisher(test.rdStr)
			if test.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, test.expectedType, rd.Type)

			// Check administrator based on type
			switch rd.Type {
			case RouteDistinguisherTypeAdministratorSubfield2Octet:
				assert.Equal(t, uint16(100), uint16(rd.Administrator[0])<<8|uint16(rd.Administrator[1]))
			case RouteDistinguisherTypeAdministratorSubfield4Octet:
				assert.Equal(t, uint32(123456), uint32(rd.Administrator[0])<<24|uint32(rd.Administrator[1])<<16|uint32(rd.Administrator[2])<<8|uint32(rd.Administrator[3]))
			case RouteDistinguisherTypeAdministratorSubfield4OctetIP:
				assert.Equal(t, net.ParseIP("192.168.1.1").To4(), net.IP(rd.Administrator))
			}

			// Test string representation matches input
			assert.Equal(t, test.rdStr, rd.String())
		})
	}
}