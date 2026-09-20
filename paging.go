package maxminddb

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"

	"github.com/oschwald/maxminddb-golang/v2/internal/mmdberrors"
)

// Pagination and resumable iteration for NetworksWithin.
//
// A resume cursor (NetworkCursor) identifies the exact DFS continuation
// position of an iteration without exposing any internal search-tree
// pointers: each pending frame is described solely by the network path
// (an IPv6-address bit prefix) that leads to it. Resuming on a new Reader
// re-walks those paths to rebuild the pointer stack.
//
// Every cursor is cryptographically bound, via an HMAC, to:
//   - a fingerprint of the database metadata (NodeCount, RecordSize,
//     IPVersion, build epoch, database type, etc.), which rejects cursors
//     replayed against a stale or otherwise different database;
//   - the prefix passed to NetworksWithinPage/NetworksPage;
//   - the set of iterator options used to produce the page.
//
// The HMAC key is a fixed library constant. Its purpose is to detect
// accidental corruption and hand-crafted tokens, not to authenticate a
// trusted producer: the token never contains secrets, file offsets, or
// search-tree pointer values.

// ErrPageSize is returned from NetworksPage and NetworksWithinPage when the
// page size is zero.
var ErrPageSize = errors.New("maxminddb: page size must be greater than zero")

// ErrCursorCorrupt is returned when a resume cursor cannot be decoded or its
// integrity check fails.
var ErrCursorCorrupt = errors.New("maxminddb: corrupt network cursor")

// ErrCursorWrongDatabase is returned when a resume cursor was produced by a
// different database, e.g. an older build replayed against an updated file.
var ErrCursorWrongDatabase = errors.New("maxminddb: network cursor is for a different database")

// ErrCursorPrefixMismatch is returned when the prefix supplied with a resume
// cursor is not the prefix the cursor was created for.
var ErrCursorPrefixMismatch = errors.New("maxminddb: network cursor prefix mismatch")

// ErrCursorOptionsMismatch is returned when the iterator options supplied
// with a resume cursor differ from the options the cursor was created with.
var ErrCursorOptionsMismatch = errors.New("maxminddb: network cursor options mismatch")

// NetworkPage is one deterministic page of results from NetworksPage or
// NetworksWithinPage.
//
// Results contains the networks in the page in the same order that Networks
// or NetworksWithin would yield them. A database error encountered while
// walking the tree is delivered as the last Result carrying an error; the
// iteration then ends and Next is nil.
//
// When Next is non-nil, more results may exist and Next must be passed to
// the next call to obtain them. Because the page size counts emitted
// networks (not visited nodes), a returned page before exhaustion always
// contains at least one Result; a region whose networks are all skipped by
// the iterator options is simply skipped within the walk. When Next is nil
// the iteration is exhausted, so callers that loop on Next can never repeat
// a call against the same empty page.
type NetworkPage struct {
	Results []Result
	Next    *NetworkCursor
}

// NetworksPage returns the first page of up to pageSize networks in the
// database. See NetworksWithinPage for pagination and resume semantics; the
// prefix bound into the cursor is ::/0 for an IPv6 database and 0.0.0.0/0
// for an IPv4-only database.
func (r *Reader) NetworksPage(pageSize int, options ...NetworksOption) (NetworkPage, error) {
	if r.Metadata.IPVersion == 6 {
		return r.NetworksWithinPage(nil, allIPv6, pageSize, options...)
	}
	return r.NetworksWithinPage(nil, allIPv4, pageSize, options...)
}

// NetworksWithinPage returns up to pageSize networks contained in prefix, in
// the deterministic order used by NetworksWithin.
//
// To start paging, pass nil as cursor. To resume, pass the NetworkCursor
// returned in the previous page's Next field. Resumption works on a freshly
// opened Reader for the same database file; it does not rely on in-memory
// iterator state.
//
// cursor must be nil on the first page; prefix and options must be identical
// on every page of a paged traversal. A page with zero Results and a non-nil
// Next is never produced: options such as SkipEmptyValues filter inside the
// walk, so an empty page always carries a nil Next. Callers should
// nevertheless terminate on a nil Next rather than looping until a page is
// non-empty.
//
// Configuration errors (invalid prefix or page size, or a cursor that is
// corrupt, stale, or bound to a different prefix, database, or option set)
// are returned as the error return. Errors in the database contents are
// delivered through Results, matching NetworksWithin.
func (r *Reader) NetworksWithinPage(
	cursor *NetworkCursor,
	prefix netip.Prefix,
	pageSize int,
	options ...NetworksOption,
) (NetworkPage, error) {
	if r.buffer == nil {
		return NetworkPage{}, errors.New("cannot call NetworksWithinPage on a closed database")
	}
	if pageSize <= 0 {
		return NetworkPage{}, fmt.Errorf("%w: got %d", ErrPageSize, pageSize)
	}

	var n networkOptions
	for _, option := range options {
		option(&n)
	}
	optionsBits := n.bits()

	if cursor != nil {
		if err := cursor.checkResume(r, prefix, optionsBits); err != nil {
			return NetworkPage{}, err
		}
	}

	w := newNetworkWalker(r, n)

	var nodes []netNode
	if cursor == nil {
		root, res := w.prepareRootResult(prefix)
		if res != nil {
			return NetworkPage{Results: []Result{*res}}, nil
		}
		nodes = []netNode{root}
	} else {
		rebuilt, err := r.rebuildFrames(cursor.state.frames)
		if err != nil {
			return NetworkPage{}, err
		}
		nodes = rebuilt
	}

	results := make([]Result, 0, min(pageSize, capInitialResults))
	remaining := w.run(nodes, pageSize, func(res Result) bool {
		results = append(results, res)
		return len(results) < pageSize
	})

	if len(remaining) == 0 {
		return NetworkPage{Results: results}, nil
	}

	next, err := newNetworkCursor(r, prefix.Masked(), optionsBits, remaining)
	if err != nil {
		return NetworkPage{}, err
	}
	return NetworkPage{Results: results, Next: next}, nil
}

const capInitialResults = 16

// networkWalker encapsulates the DFS shared by the iterator API and the
// paging API. The two entry points produce byte-identical traversal orders.
type networkWalker struct {
	r *Reader
	n networkOptions
}

func newNetworkWalker(r *Reader, n networkOptions) networkWalker {
	return networkWalker{r: r, n: n}
}

// prepareRoot locates the root frame of the iteration for prefix. On a
// configuration or lookup error it yields an error Result exactly as the
// historical NetworksWithin iterator did and returns ok == false.
func (w networkWalker) prepareRoot(
	prefix netip.Prefix,
	yield func(Result) bool,
) (netNode, bool) {
	root, res := w.prepareRootResult(prefix)
	if res != nil {
		yield(*res)
		return netNode{}, false
	}
	return root, true
}

func (w networkWalker) prepareRootResult(prefix netip.Prefix) (netNode, *Result) {
	r := w.r
	if !prefix.IsValid() {
		return netNode{}, &Result{err: errors.New("invalid prefix")}
	}
	if r.Metadata.IPVersion == 4 && prefix.Addr().Is6() {
		return netNode{}, &Result{err: fmt.Errorf(
			"error getting networks with '%s': you attempted to use an IPv6 network in an IPv4-only database",
			prefix,
		)}
	}

	ip := prefix.Addr()
	netIP := ip
	stopBit := prefix.Bits()
	if ip.Is4() {
		netIP = v4ToV16(ip)
		stopBit += 96
	}

	if stopBit > 128 {
		return netNode{}, &Result{
			err: errors.New("invalid prefix: exceeds IPv6 maximum of 128 bits"),
		}
	}

	pointer, bit, err := r.traverseTree(ip, 0, stopBit)
	if err != nil {
		return netNode{}, &Result{ip: ip, err: err}
	}

	networkPrefix, err := netIP.Prefix(bit)
	if err != nil {
		return netNode{}, &Result{
			ip:        ip,
			prefixLen: uint8(bit),
			err:       fmt.Errorf("prefixing %s with %d: %w", netIP, bit, err),
		}
	}

	return netNode{
		ip:      networkPrefix.Addr(),
		bit:     uint(bit),
		pointer: pointer,
	}, nil
}

// run walks the DFS starting from nodes. It yields each visible network.
// limit > 0 caps the number of successful yields; limit == 0 means unlimited.
// It returns the frames that still need visiting when a limit stopped the
// walk (the continuation stack), or nil when the walk finished.
func (w networkWalker) run(
	nodes []netNode,
	limit int,
	yield func(Result) bool,
) []netNode {
	r := w.r
	n := w.n

	for len(nodes) > 0 {
		node := nodes[len(nodes)-1]
		nodes = nodes[:len(nodes)-1]

		for {
			if node.pointer == r.Metadata.NodeCount {
				if n.includeEmptyNetworks {
					ok := yield(Result{
						ip:        mappedIP(node.ip),
						offset:    notFound,
						prefixLen: uint8(node.bit),
					})
					if !ok {
						// This leaf was the final emitted network. It must
						// not be re-pushed or resume would yield it twice.
						return nodes
					}
				}
				break
			}
			// This skips IPv4 aliases without hardcoding the networks that
			// the writer currently aliases.
			if !n.includeAliasedNetworks && r.ipv4Start != 0 &&
				node.pointer == r.ipv4Start && !isInIPv4Subtree(node.ip) {
				break
			}

			if node.pointer > r.Metadata.NodeCount {
				offset, err := r.resolveDataPointer(node.pointer)

				if err == nil && n.skipEmptyValues {
					var isEmpty bool
					isEmpty, err = r.decoder.IsEmptyValueAt(uint(offset))
					if err == nil && isEmpty {
						break
					}
				}

				ok := yield(Result{
					reader:    r,
					ip:        mappedIP(node.ip),
					offset:    uint(offset),
					prefixLen: uint8(node.bit),
					err:       err,
				})
				if !ok {
					return nodes
				}
				break
			}
			ipRight := node.ip.As16()
			if len(ipRight) <= int(node.bit>>3) {
				displayAddr := node.ip
				if isInIPv4Subtree(node.ip) {
					displayAddr = v6ToV4(displayAddr)
				}

				res := Result{
					ip:        displayAddr,
					prefixLen: uint8(node.bit),
				}
				res.err = mmdberrors.NewInvalidDatabaseError(
					"invalid search tree at %s", res.Prefix(),
				)

				yield(res)

				return nil
			}
			ipRight[node.bit>>3] |= 1 << (7 - (node.bit % 8))

			baseOffset := node.pointer * r.nodeOffsetMult
			leftPointer, rightPointer, err := readNodePairBySize(
				r.buffer,
				baseOffset,
				r.Metadata.RecordSize,
			)
			if err != nil {
				yield(Result{
					ip:        mappedIP(node.ip),
					prefixLen: uint8(node.bit),
					err:       err,
				})
				return nil
			}

			node.bit++
			nodes = append(nodes, netNode{
				pointer: rightPointer,
				ip:      netip.AddrFrom16(ipRight),
				bit:     node.bit,
			})

			node.pointer = leftPointer
		}
	}
	runtime.KeepAlive(r)
	return nil
}

func (n networkOptions) bits() byte {
	var b byte
	if n.includeAliasedNetworks {
		b |= optionIncludeAliasedNetworks
	}
	if n.includeEmptyNetworks {
		b |= optionIncludeEmptyNetworks
	}
	if n.skipEmptyValues {
		b |= optionSkipEmptyValues
	}
	return b
}

const (
	optionIncludeAliasedNetworks byte = 1 << 0
	optionIncludeEmptyNetworks   byte = 1 << 1
	optionSkipEmptyValues        byte = 1 << 2
	optionKnownMask              byte = optionIncludeAliasedNetworks |
		optionIncludeEmptyNetworks |
		optionSkipEmptyValues
)

// cursorVersion is the supported cursor payload format.
const cursorVersion byte = 1

// cursorState is the decoded, validated contents of a resume cursor.
type cursorState struct {
	prefix      netip.Prefix
	family      byte // 4 or 6
	options     byte
	frames      []frameState
	fingerprint [32]byte
}

// frameState is one pending DFS frame identified by its network path rather
// than by a search-tree pointer. ip is always a 16-byte IPv6 representation
// (IPv4 paths use the ::a.b.c.d form used throughout the traversal) and bits
// is the depth of that path, in 1..128.
type frameState struct {
	ip   [16]byte
	bits byte
}

// NetworkCursor is an opaque, verifiable resume position returned by
// [Reader.NetworksPage] and [Reader.NetworksWithinPage].
//
// NetworkCursor implements encoding.TextMarshaler and
// encoding.TextUnmarshaler, and its zero value is not a valid cursor. A
// cursor is usable with any [Reader] opened on the same database, including
// in another process. It must be resumed with the same prefix and iterator
// options it was created for.
type NetworkCursor struct {
	state cursorState
}

// MarshalText implements encoding.TextMarshaler.
func (c NetworkCursor) MarshalText() ([]byte, error) {
	payload, err := c.marshalPayload()
	if err != nil {
		return nil, err
	}
	return []byte(encodeCursor(payload)), nil
}

// String returns the opaque token string for the cursor.
func (c NetworkCursor) String() string {
	text, err := c.MarshalText()
	if err != nil {
		return ""
	}
	return string(text)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (c *NetworkCursor) UnmarshalText(text []byte) error {
	state, err := parseCursorToken(string(text))
	if err != nil {
		return err
	}
	c.state = state
	return nil
}

// ParseNetworkCursor decodes a token previously produced from a NetworkCursor.
// It validates the token's structure and integrity but does not bind it to a
// particular Reader, prefix, or option set; that binding is verified when the
// cursor is used to resume.
func ParseNetworkCursor(token string) (*NetworkCursor, error) {
	state, err := parseCursorToken(token)
	if err != nil {
		return nil, err
	}
	return &NetworkCursor{state: state}, nil
}

// Prefix returns the prefix that the cursor was created for.
func (c NetworkCursor) Prefix() netip.Prefix {
	return c.state.prefix
}
