package maxminddb

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"hash/fnv"
	"net/netip"
)

// ErrInvalidNetworksToken is returned, wrapped with diagnostic context, by
// [Reader.NetworksWithinPage] when the supplied resume token is malformed,
// corrupt, or does not match the database, prefix, or iterator options it was
// created for. Use errors.Is to detect it.
var ErrInvalidNetworksToken = errors.New("maxminddb: invalid networks resume token")

// NetworksPage is a single page of results from [Reader.NetworksWithinPage].
type NetworksPage struct {
	// Results holds up to the requested page size of networks in the same
	// deterministic depth-first order produced by [Reader.NetworksWithin].
	// Individual Results may carry per-record errors, exactly as with
	// [Reader.NetworksWithin].
	Results []Result

	// ResumeToken resumes the traversal after the last Result of this page
	// when passed to [Reader.NetworksWithinPage] with the same database,
	// prefix, and options. It is empty once the traversal is complete. An
	// empty page always has an empty ResumeToken, so paging terminates.
	ResumeToken string
}

// NetworksWithinPage returns one page of the networks in the database which
// are contained in the given prefix, plus an opaque resume token for fetching
// the following page. It is the paginated counterpart of
// [Reader.NetworksWithin]: concatenating the Results of every page, in order,
// yields exactly the sequence that NetworksWithin would produce for the same
// prefix and options.
//
// pageSize must be at least 1. Pass an empty resumeToken for the first page
// and the returned NetworksPage.ResumeToken for each subsequent page; the
// traversal is complete when ResumeToken is empty. A page is either exactly
// pageSize long or final (empty ResumeToken); an empty page is always final,
// so callers looping until the token is empty cannot spin.
//
// The resume token is bound to the database metadata (database type, binary
// format version, build epoch, IP version, node count, and record size), to
// the normalized query prefix, and to the iterator options. Resuming with a
// different database, prefix, or option set fails with an error wrapping
// [ErrInvalidNetworksToken]. The token encodes only a network-space position
// (an IP address and prefix length); it contains no search-tree node pointers
// or data-section offsets, and it may be used on a new Reader opened on the
// same database file.
func (r *Reader) NetworksWithinPage(
	prefix netip.Prefix,
	pageSize int,
	resumeToken string,
	options ...NetworksOption,
) (NetworksPage, error) {
	if pageSize < 1 {
		return NetworksPage{}, fmt.Errorf(
			"page size must be at least 1, got %d", pageSize,
		)
	}

	var n networkOptions
	for _, option := range options {
		option(&n)
	}

	it, errResult := r.newNetworkIterator(prefix, n)
	if errResult != nil {
		return NetworksPage{}, errResult.err
	}

	if resumeToken != "" {
		resumeIP, resumeBit, err := r.decodeNetworksToken(resumeToken, it)
		if err != nil {
			return NetworksPage{}, err
		}
		if err := it.resume(resumeIP, resumeBit); err != nil {
			return NetworksPage{}, fmt.Errorf(
				"%w: cannot resume at token position: %w",
				ErrInvalidNetworksToken, err,
			)
		}
	}

	page := NetworksPage{Results: make([]Result, 0, pageSize)}
	for len(page.Results) < pageSize {
		result, ok := it.next()
		if !ok {
			return page, nil
		}
		page.Results = append(page.Results, result)
	}

	resumeIP, resumeBit, ok := it.resumePoint()
	if !ok {
		// The page ended exactly at the end of the traversal.
		return page, nil
	}
	page.ResumeToken = r.encodeNetworksToken(it, resumeIP, resumeBit)
	return page, nil
}

// Binary layout of the resume token before base64url encoding:
//
//	1 byte  token format version
//	8 bytes metadata fingerprint (FNV-1a 64 of the bound metadata fields)
//	1 byte  iterator options bitmask
//	16 bytes normalized query prefix address (IPv4 mapped into ::/96)
//	1 byte  normalized query prefix length
//	16 bytes resume position address
//	1 byte  resume position prefix length
//	4 bytes CRC-32 (IEEE) of all preceding bytes
const (
	networksTokenVersion = 1
	networksTokenSize    = 1 + 8 + 1 + 16 + 1 + 16 + 1 + 4
)

var networksTokenEncoding = base64.RawURLEncoding

func (r *Reader) encodeNetworksToken(
	it *networkIterator,
	resumeIP netip.Addr,
	resumeBit uint,
) string {
	buf := make([]byte, 0, networksTokenSize)
	buf = append(buf, networksTokenVersion)
	buf = binary.BigEndian.AppendUint64(buf, r.metadataFingerprint())
	buf = append(buf, it.opts.bitmask())
	prefixAddr := it.netIP.As16()
	buf = append(buf, prefixAddr[:]...)
	buf = append(buf, byte(it.stopBit))
	resumeAddr := resumeIP.As16()
	buf = append(buf, resumeAddr[:]...)
	buf = append(buf, byte(resumeBit))
	checksum := crc32.ChecksumIEEE(buf)
	buf = binary.BigEndian.AppendUint32(buf, checksum)
	return networksTokenEncoding.EncodeToString(buf)
}

func (r *Reader) decodeNetworksToken(
	token string,
	it *networkIterator,
) (netip.Addr, uint, error) {
	raw, err := networksTokenEncoding.DecodeString(token)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf(
			"%w: not valid base64url: %v", ErrInvalidNetworksToken, err,
		)
	}
	if len(raw) != networksTokenSize {
		return netip.Addr{}, 0, fmt.Errorf(
			"%w: expected %d bytes, got %d",
			ErrInvalidNetworksToken, networksTokenSize, len(raw),
		)
	}
	stored := binary.BigEndian.Uint32(raw[networksTokenSize-4:])
	computed := crc32.ChecksumIEEE(raw[:networksTokenSize-4])
	if stored != computed {
		return netip.Addr{}, 0, fmt.Errorf(
			"%w: checksum mismatch (token is corrupt or truncated)",
			ErrInvalidNetworksToken,
		)
	}
	if raw[0] != networksTokenVersion {
		return netip.Addr{}, 0, fmt.Errorf(
			"%w: unsupported token version %d (this library understands %d)",
			ErrInvalidNetworksToken, raw[0], networksTokenVersion,
		)
	}

	fingerprint := binary.BigEndian.Uint64(raw[1:9])
	if fingerprint != r.metadataFingerprint() {
		m := r.Metadata
		return netip.Addr{}, 0, fmt.Errorf(
			"%w: token was created for a different database "+
				"(this database: type %q, format %d.%d, build epoch %d, "+
				"IP version %d, %d nodes, %d-bit records)",
			ErrInvalidNetworksToken,
			m.DatabaseType,
			m.BinaryFormatMajorVersion, m.BinaryFormatMinorVersion,
			m.BuildEpoch, m.IPVersion, m.NodeCount, m.RecordSize,
		)
	}

	if raw[9] != it.opts.bitmask() {
		return netip.Addr{}, 0, fmt.Errorf(
			"%w: token was created with different iterator options "+
				"(IncludeAliasedNetworks, IncludeNetworksWithoutData, SkipEmptyValues)",
			ErrInvalidNetworksToken,
		)
	}

	tokenPrefix := netip.AddrFrom16([16]byte(raw[10:26]))
	tokenBits := int(raw[26])
	if tokenPrefix != it.netIP || tokenBits != it.stopBit {
		return netip.Addr{}, 0, fmt.Errorf(
			"%w: token was created for prefix %s/%d, not %s/%d",
			ErrInvalidNetworksToken,
			tokenPrefix, tokenBits, it.netIP, it.stopBit,
		)
	}

	resumeIP := netip.AddrFrom16([16]byte(raw[27:43]))
	resumeBit := uint(raw[43])
	return resumeIP, resumeBit, nil
}

// bitmask encodes the iterator options that change which networks are
// visible, so that a token cannot be replayed under different visibility
// rules.
func (n networkOptions) bitmask() byte {
	var mask byte
	if n.includeAliasedNetworks {
		mask |= 1
	}
	if n.includeEmptyNetworks {
		mask |= 2
	}
	if n.skipEmptyValues {
		mask |= 4
	}
	return mask
}

// metadataFingerprint binds a resume token to the database it was created
// from. Two databases that differ in any of these fields cannot safely share
// a traversal position.
func (r *Reader) metadataFingerprint() uint64 {
	m := r.Metadata
	h := fnv.New64a()
	h.Write([]byte(m.DatabaseType))
	h.Write([]byte{0})
	var num [8]byte
	for _, v := range []uint{
		m.BinaryFormatMajorVersion,
		m.BinaryFormatMinorVersion,
		m.BuildEpoch,
		m.IPVersion,
		m.NodeCount,
		m.RecordSize,
	} {
		binary.BigEndian.PutUint64(num[:], uint64(v))
		h.Write(num[:])
	}
	return h.Sum64()
}
