package maxminddb

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Token wire format:
//
//	base64url(payload) "." base64url(hmac_sha256(key, payload))
//
// payload (all integers big-endian):
//
//	byte  0: version (1)
//	bytes 1..32: metadata fingerprint
//	byte 33: address family (4 or 6)
//	byte 34: prefix length in the address family (0..32 for IPv4, 0..128)
//	byte 35: tree-path depth of the prefix (prefix length, or length+96 for
//	         IPv4 prefixes in a 16-byte representation)
//	bytes 36..51: prefix address as 16 bytes (masked to the tree-path depth)
//	byte 52: options bits
//	bytes 53..54: number of frames (0..128)
//	then frames, each:
//	    bytes 0..15: frame path address (16 bytes)
//	    byte 16: frame bit depth (1..128)

const (
	cursorPayloadFixedLen = 56
	cursorFrameLen        = 17
	cursorMaxFrames       = 128
)

// cursorMACKey is a fixed, non-secret library constant. The MAC detects
// corrupted and hand-crafted tokens; it does not gate access to hidden data,
// as the token only carries address paths and metadata.
var cursorMACKey = []byte("maxminddb-golang/network-cursor/v1")

func encodeCursor(payload []byte) string {
	mac := hmac.New(sha256.New, cursorMACKey)
	mac.Write(payload)
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(mac.Sum(nil))
}

func parseCursorToken(token string) (cursorState, error) {
	var state cursorState

	dot := -1
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			dot = i
			break
		}
	}
	if dot <= 0 {
		return state, fmt.Errorf("%w: malformed token", ErrCursorCorrupt)
	}

	payloadPart, macPart := token[:dot], token[dot+1:]

	payload, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return state, fmt.Errorf("%w: payload is not valid base64: %v", ErrCursorCorrupt, err)
	}

	var gotMAC [sha256.Size]byte
	mac := hmac.New(sha256.New, cursorMACKey)
	mac.Write(payload)
	wantMAC := mac.Sum(nil)
	decodedMAC, err := base64.RawURLEncoding.DecodeString(macPart)
	if err != nil || len(decodedMAC) != len(gotMAC) {
		return state, fmt.Errorf("%w: integrity tag is not valid base64", ErrCursorCorrupt)
	}
	copy(gotMAC[:], decodedMAC)
	if !hmac.Equal(gotMAC[:], wantMAC) {
		return state, fmt.Errorf("%w: integrity check failed", ErrCursorCorrupt)
	}

	state, err = unmarshalCursorPayload(payload)
	if err != nil {
		return cursorState{}, err
	}
	return state, nil
}

func unmarshalCursorPayload(payload []byte) (cursorState, error) {
	var state cursorState
	if len(payload) < cursorPayloadFixedLen {
		return state, fmt.Errorf("%w: payload too short (%d bytes)", ErrCursorCorrupt, len(payload))
	}
	if payload[0] != cursorVersion {
		return state, fmt.Errorf(
			"%w: unsupported cursor version %d",
			ErrCursorCorrupt,
			payload[0],
		)
	}

	copy(state.fingerprint[:], payload[1:33])

	family := payload[33]
	if family != 4 && family != 6 {
		return state, fmt.Errorf("%w: invalid address family %d", ErrCursorCorrupt, family)
	}
	state.family = family

	prefixLen := payload[34]
	maxPrefixLen := uint8(128)
	if family == 4 {
		maxPrefixLen = 32
	}
	if prefixLen > maxPrefixLen {
		return state, fmt.Errorf(
			"%w: prefix length %d exceeds %d",
			ErrCursorCorrupt,
			prefixLen,
			maxPrefixLen,
		)
	}

	pathDepth := payload[35]
	maxPathDepth := uint8(128)
	if family == 4 {
		maxPathDepth = 128
		if pathDepth != prefixLen+96 {
			return state, fmt.Errorf(
				"%w: IPv4 path depth %d is not prefix length %d + 96",
				ErrCursorCorrupt,
				pathDepth,
				prefixLen,
			)
		}
	} else if pathDepth != prefixLen {
		return state, fmt.Errorf(
			"%w: path depth %d does not match prefix length %d",
			ErrCursorCorrupt,
			pathDepth,
			prefixLen,
		)
	}
	if pathDepth > maxPathDepth {
		return state, fmt.Errorf("%w: path depth %d exceeds 128",
			ErrCursorCorrupt, pathDepth)
	}

	var addr [16]byte
	copy(addr[:], payload[36:52])
	if hasBitsOutsideMask(addr, uint(pathDepth)) {
		return state, fmt.Errorf("%w: prefix address has host bits set", ErrCursorCorrupt)
	}
	state.prefix = prefixFromV16(addr, uint(prefixLen), family)

	optionsBits := payload[52]
	if optionsBits&^optionKnownMask != 0 {
		return state, fmt.Errorf(
			"%w: unknown cursor option bits 0x%02x",
			ErrCursorCorrupt,
			optionsBits,
		)
	}
	state.options = optionsBits

	frameCount := int(binary.BigEndian.Uint16(payload[53:55]))
	if frameCount > cursorMaxFrames {
		return state, fmt.Errorf("%w: cursor frame count %d exceeds %d",
			ErrCursorCorrupt, frameCount, cursorMaxFrames)
	}
	wantLen := cursorPayloadFixedLen + frameCount*cursorFrameLen
	if len(payload) != wantLen {
		return state, fmt.Errorf(
			"%w: payload length %d does not match %d frames",
			ErrCursorCorrupt,
			len(payload),
			frameCount,
		)
	}

	state.frames = make([]frameState, 0, frameCount)
	off := cursorPayloadFixedLen
	for range frameCount {
		var ip [16]byte
		copy(ip[:], payload[off:off+16])
		bits := payload[off+16]
		if bits < 1 || bits > 128 {
			return state, fmt.Errorf("%w: frame depth %d out of range", ErrCursorCorrupt, bits)
		}
		if hasBitsOutsideMask(ip, uint(bits)) {
			return state, fmt.Errorf("%w: frame path has bits below its depth", ErrCursorCorrupt)
		}
		state.frames = append(state.frames, frameState{ip: ip, bits: bits})
		off += cursorFrameLen
	}

	return state, nil
}

func hasBitsOutsideMask(addr [16]byte, bits uint) bool {
	if bits >= 128 {
		return false
	}
	masked := addr
	zeroHostBits(&masked, bits)
	return masked != addr
}

// zeroHostBits clears all bits at positions >= bits in place.
func zeroHostBits(addr *[16]byte, bits uint) {
	if bits >= 128 {
		return
	}
	fullBytes := bits / 8
	for i := fullBytes + 1; i < 16; i++ {
		addr[i] = 0
	}
	if bitInByte := bits % 8; bitInByte != 0 {
		addr[fullBytes] &= ^byte(0xFF >> bitInByte)
	} else {
		addr[fullBytes] = 0
	}
}

func prefixFromV16(addr [16]byte, bits uint, family byte) netip.Prefix {
	v16 := netip.AddrFrom16(addr)
	if family == 4 {
		return netip.PrefixFrom(v6ToV4(v16), int(bits))
	}
	return netip.PrefixFrom(v16, int(bits))
}

func (c NetworkCursor) marshalPayload() ([]byte, error) {
	s := c.state
	if !s.prefix.IsValid() {
		return nil, fmt.Errorf("%w: cursor has no prefix", ErrCursorCorrupt)
	}
	if len(s.frames) > cursorMaxFrames {
		return nil, fmt.Errorf("%w: cursor frame count exceeds %d",
			ErrCursorCorrupt, cursorMaxFrames)
	}

	payload := make([]byte, cursorPayloadFixedLen+len(s.frames)*cursorFrameLen)
	payload[0] = cursorVersion
	copy(payload[1:33], s.fingerprint[:])
	payload[33] = s.family
	prefixBits := s.prefix.Bits()
	pathBits := prefixBits
	if s.family == 4 {
		// IPv4 prefixes are stored as 16-byte ::a.b.c.d paths at depth
		// 96 + IPv4 prefix length.
		pathBits += 96
	}
	payload[34] = byte(prefixBits)
	payload[35] = byte(pathBits)

	var addr16 [16]byte
	if s.family == 4 {
		addr16 = v4ToV16(s.prefix.Addr()).As16()
	} else {
		addr16 = s.prefix.Addr().As16()
	}
	copy(payload[36:52], addr16[:])
	payload[52] = s.options
	binary.BigEndian.PutUint16(payload[53:55], uint16(len(s.frames)))

	off := cursorPayloadFixedLen
	for _, f := range s.frames {
		copy(payload[off:off+16], f.ip[:])
		payload[off+16] = f.bits
		off += cursorFrameLen
	}
	return payload, nil
}
