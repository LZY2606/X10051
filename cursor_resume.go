package maxminddb

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"

	"github.com/oschwald/maxminddb-golang/v2/internal/mmdberrors"
)

// newNetworkCursor builds a cursor for the given traversal configuration and
// pending DFS stack. The stack never contains internal pointers in the token.
func newNetworkCursor(
	r *Reader,
	prefix netip.Prefix,
	optionsBits byte,
	remaining []netNode,
) (*NetworkCursor, error) {
	family := byte(6)
	if prefix.Addr().Is4() {
		family = 4
	}

	frames := make([]frameState, 0, len(remaining))
	for _, node := range remaining {
		if node.bit < 1 || node.bit > 128 {
			return nil, mmdberrors.NewInvalidDatabaseError(
				"cannot encode cursor frame at invalid depth %d",
				node.bit,
			)
		}
		frames = append(frames, frameState{
			ip:   node.ip.As16(),
			bits: byte(node.bit),
		})
	}

	return &NetworkCursor{
		state: cursorState{
			prefix:      prefix,
			family:      family,
			options:     optionsBits,
			frames:      frames,
			fingerprint: r.metadataFingerprint,
		},
	}, nil
}

// checkResume verifies that c may resume the traversal described by prefix
// and optionsBits against r.
func (c *NetworkCursor) checkResume(r *Reader, prefix netip.Prefix, optionsBits byte) error {
	s := c.state
	if !s.prefix.IsValid() {
		return fmt.Errorf("%w: cursor has no bound prefix", ErrCursorCorrupt)
	}

	if s.fingerprint != r.metadataFingerprint {
		return fmt.Errorf(
			"%w: cursor metadata fingerprint does not match the open database "+
				"(database_type=%q build_epoch=%d node_count=%d record_size=%d ip_version=%d)",
			ErrCursorWrongDatabase,
			r.Metadata.DatabaseType,
			r.Metadata.BuildEpoch,
			r.Metadata.NodeCount,
			r.Metadata.RecordSize,
			r.Metadata.IPVersion,
		)
	}

	// A cursor for an IPv4 prefix cannot be resumed in an IPv4-only database
	// via an IPv6 prefix (or vice versa); compare canonical prefixes.
	if !prefix.IsValid() || s.prefix != prefix.Masked() {
		return fmt.Errorf(
			"%w: cursor was created for %s but resume requested %s",
			ErrCursorPrefixMismatch,
			s.prefix,
			prefixString(prefix),
		)
	}
	if s.family == 4 != prefix.Addr().Is4() {
		return fmt.Errorf(
			"%w: cursor address family does not match resume prefix %s",
			ErrCursorPrefixMismatch,
			prefixString(prefix),
		)
	}

	if s.options != optionsBits {
		return fmt.Errorf(
			"%w: cursor options 0x%02x do not match resume options 0x%02x",
			ErrCursorOptionsMismatch,
			s.options,
			optionsBits,
		)
	}
	return nil
}

func prefixString(prefix netip.Prefix) string {
	if !prefix.IsValid() {
		return "<invalid prefix>"
	}
	return prefix.Masked().String()
}

// rebuildFrames re-walks the tree along every stored path to reconstruct the
// pointer for each pending DFS frame. Paths are stored as network prefixes,
// so this recovers the identical frame without recording internal offsets.
func (r *Reader) rebuildFrames(frames []frameState) ([]netNode, error) {
	nodes := make([]netNode, 0, len(frames))
	for _, frame := range frames {
		v16 := netip.AddrFrom16(frame.ip)

		var pointer uint
		var bit int
		var err error
		if r.Metadata.IPVersion == 4 && isInIPv4Subtree(v16) {
			pointer, bit, err = r.traverseTree(v6ToV4(v16), 0, int(frame.bits))
		} else {
			pointer, bit, err = r.traverseTree(v16, 0, int(frame.bits))
		}
		if err != nil {
			return nil, fmt.Errorf(
				"%w: unable to rebuild cursor path %s/%d against the database: %v",
				ErrCursorWrongDatabase,
				mappedIP(v16),
				frame.bits,
				err,
			)
		}
		if bit != int(frame.bits) {
			return nil, fmt.Errorf(
				"%w: cursor path %s/%d resolves only to depth %d in this database",
				ErrCursorWrongDatabase,
				mappedIP(v16),
				frame.bits,
				bit,
			)
		}
		nodes = append(nodes, netNode{
			ip:      v16,
			bit:     uint(frame.bits),
			pointer: pointer,
		})
	}
	return nodes, nil
}

// fingerprintMetadata computes a stable fingerprint over every metadata field
// that defines the shape or identity of the search tree and data. Two
// databases with identical metadata cannot be told apart by a cursor; this is
// documented in the CHANGELOG.
func fingerprintMetadata(m Metadata) [sha256.Size]byte {
	h := sha256.New()
	writeString := func(s string) {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
		h.Write(lenBuf[:])
		h.Write([]byte(s))
	}
	writeUint := func(v uint64) {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], v)
		h.Write(buf[:])
	}

	writeString(m.DatabaseType)
	writeUint(uint64(m.BuildEpoch))
	writeUint(uint64(m.IPVersion))
	writeUint(uint64(m.NodeCount))
	writeUint(uint64(m.RecordSize))
	writeUint(uint64(m.BinaryFormatMajorVersion))
	writeUint(uint64(m.BinaryFormatMinorVersion))

	keys := make([]string, 0, len(m.Description))
	for k := range m.Description {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeUint(uint64(len(keys)))
	for _, k := range keys {
		writeString(k)
		writeString(m.Description[k])
	}

	langs := append([]string(nil), m.Languages...)
	sort.Strings(langs)
	writeUint(uint64(len(langs)))
	for _, lang := range langs {
		writeString(lang)
	}

	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum
}
