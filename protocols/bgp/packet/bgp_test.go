package packet

import (
	"github.com/bio-routing/bio-rd/util"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAFName(t *testing.T) {
	afiIPv4 := util.AFName(1, 1)
	assert.Equal(t, "IPv4", afiIPv4)

	afiIPv6 := util.AFName(2, 1)
	assert.Equal(t, "IPv6", afiIPv6)

	afiUnknown := util.AFName(0, 0)
	assert.Equal(t, "Unknown AFI/SAFI", afiUnknown)

	afiVPNv4 := util.AFName(1, 128)
	assert.Equal(t, "VPNv4", afiVPNv4)

	afiVPNv6 := util.AFName(2, 128)
	assert.Equal(t, "VPNv6", afiVPNv6)

	afiIPv4LU := util.AFName(1, 4)
	assert.Equal(t, "IPv4LU", afiIPv4LU)

	afiIPv6LU := util.AFName(2, 4)
	assert.Equal(t, "IPv6LU", afiIPv6LU)
}

func TestBGPErrorError(t *testing.T) {
	e := BGPError{
		ErrorCode:    2,
		ErrorSubCode: 3,
		ErrorStr:     "Unknown Error TestBGPErrorError",
	}

	actual := e.Error()
	expected := "Unknown Error TestBGPErrorError"
	assert.Equal(t, expected, actual)
}

func TestPeerRoleName(t *testing.T) {
	tests := []struct {
		peerRole     uint8
		peerRoleName string
	}{
		{
			peerRole:     PeerRoleRoleProvider,
			peerRoleName: "Provider",
		},
		{
			peerRole:     PeerRoleRoleRS,
			peerRoleName: "RS",
		},
		{
			peerRole:     PeerRoleRoleRSClient,
			peerRoleName: "RS-Client",
		},
		{
			peerRole:     PeerRoleRoleCustomer,
			peerRoleName: "Customer",
		},
		{
			peerRole:     PeerRoleRolePeer,
			peerRoleName: "Peer",
		},
		{
			peerRole:     123,
			peerRoleName: "Unknown",
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.peerRoleName, PeerRoleName(test.peerRole))
	}
}
