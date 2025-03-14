package util

import "math"

// BytesInAddr gets the amount of bytes needed to encode an NLRI of prefix length pfxlen
func BytesInAddr(pfxlen uint8) uint8 {
	return uint8(math.Ceil(float64(pfxlen) / 8))
}
