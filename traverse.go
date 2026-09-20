package maxminddb

import (
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"runtime"

	"github.com/oschwald/maxminddb-golang/v2/internal/mmdberrors"
)

// Internal structure used to keep track of nodes we still need to visit.
type netNode struct {
	ip      netip.Addr
	bit     uint
	pointer uint
}

type networkOptions struct {
	includeAliasedNetworks bool
	includeEmptyNetworks   bool
	skipEmptyValues        bool
}

var (
	allIPv4 = netip.MustParsePrefix("0.0.0.0/0")
	allIPv6 = netip.MustParsePrefix("::/0")
)

// NetworksOption are options for Networks and NetworksWithin.
type NetworksOption func(*networkOptions)

// IncludeAliasedNetworks is an option for Networks and NetworksWithin
// that makes them iterate over aliases of the IPv4 subtree in an IPv6
// database, e.g., ::ffff:0:0/96, 2001::/32, and 2002::/16.
func IncludeAliasedNetworks() NetworksOption {
	return func(networks *networkOptions) {
		networks.includeAliasedNetworks = true
	}
}

// IncludeNetworksWithoutData is an option for Networks and NetworksWithin
// that makes them include networks without any data in the iteration.
func IncludeNetworksWithoutData() NetworksOption {
	return func(networks *networkOptions) {
		networks.includeEmptyNetworks = true
	}
}

// SkipEmptyValues is an option for Networks and NetworksWithin that makes
// them skip networks whose data is an empty map or empty array. This is
// useful for databases that store empty maps or arrays for records without
// meaningful data, allowing iteration over only records with actual content.
func SkipEmptyValues() NetworksOption {
	return func(networks *networkOptions) {
		networks.skipEmptyValues = true
	}
}

// Networks returns an iterator that can be used to traverse the networks in
// the database.
//
// Please note that a MaxMind DB may map IPv4 networks into several locations
// in an IPv6 database. This iterator will only iterate over these once by
// default. To iterate over all the IPv4 network locations, use the
// [IncludeAliasedNetworks] option.
//
// Networks without data are excluded by default. To include them, use
// [IncludeNetworksWithoutData].
func (r *Reader) Networks(options ...NetworksOption) iter.Seq[Result] {
	if r.Metadata.IPVersion == 6 {
		return r.NetworksWithin(allIPv6, options...)
	}
	return r.NetworksWithin(allIPv4, options...)
}

// NetworksWithin returns an iterator that can be used to traverse the networks
// in the database which are contained in a given prefix.
//
// Please note that a MaxMind DB may map IPv4 networks into several locations
// in an IPv6 database. This iterator will only iterate over these once by
// default. To iterate over all the IPv4 network locations, use the
// [IncludeAliasedNetworks] option.
//
// If the provided prefix is contained within a network in the database, the
// iterator will iterate over exactly one network, the containing network.
//
// Networks without data are excluded by default. To include them, use
// [IncludeNetworksWithoutData].
func (r *Reader) NetworksWithin(prefix netip.Prefix, options ...NetworksOption) iter.Seq[Result] {
	return func(yield func(Result) bool) {
		var n networkOptions
		for _, option := range options {
			option(&n)
		}

		it, errResult := r.newNetworkIterator(prefix, n)
		if errResult != nil {
			yield(*errResult)
			return
		}

		for {
			result, ok := it.next()
			if !ok {
				return
			}
			if !yield(result) {
				return
			}
		}
	}
}

// networkIterator holds the state of a depth-first traversal of the search
// tree. The pending-node stack is fully determined by the path from the
// traversal root to the next node to visit, which is what makes the traversal
// resumable from a compact, network-space-only checkpoint.
type networkIterator struct {
	reader *Reader
	opts   networkOptions
	// netIP and stopBit are the normalized form of the query prefix: IPv4
	// addresses are mapped into the ::/96 subtree and stopBit is adjusted by
	// 96. Two query prefixes with the same normalized form traverse
	// identically.
	netIP   netip.Addr
	stopBit int
	nodes   []netNode
}

// newNetworkIterator validates the prefix and locates the traversal root. On
// failure it returns the Result that the iterator-based APIs yield for the
// same input, so that all entry points report identical errors.
func (r *Reader) newNetworkIterator(
	prefix netip.Prefix,
	n networkOptions,
) (*networkIterator, *Result) {
	if !prefix.IsValid() {
		return nil, &Result{
			err: errors.New("invalid prefix"),
		}
	}
	if r.Metadata.IPVersion == 4 && prefix.Addr().Is6() {
		return nil, &Result{
			err: fmt.Errorf(
				"error getting networks with '%s': you attempted to use an IPv6 network in an IPv4-only database",
				prefix,
			),
		}
	}

	ip := prefix.Addr()
	netIP := ip
	stopBit := prefix.Bits()
	if ip.Is4() {
		netIP = v4ToV16(ip)
		stopBit += 96
	}

	if stopBit > 128 {
		return nil, &Result{
			err: errors.New("invalid prefix: exceeds IPv6 maximum of 128 bits"),
		}
	}

	pointer, bit, err := r.traverseTree(ip, 0, stopBit)
	if err != nil {
		return nil, &Result{
			ip:  ip,
			err: err,
		}
	}

	networkPrefix, err := netIP.Prefix(bit)
	if err != nil {
		return nil, &Result{
			ip:        ip,
			prefixLen: uint8(bit),
			err:       fmt.Errorf("prefixing %s with %d: %w", netIP, bit, err),
		}
	}

	nodes := make([]netNode, 0, 64)
	nodes = append(nodes,
		netNode{
			ip:      networkPrefix.Addr(),
			bit:     uint(bit),
			pointer: pointer,
		},
	)

	return &networkIterator{
		reader:  r,
		opts:    n,
		netIP:   netIP,
		stopBit: stopBit,
		nodes:   nodes,
	}, nil
}

// next returns the next visible network in depth-first order. ok is false
// once the traversal is complete. Structural database errors are returned as
// a final Result carrying the error, after which ok is false.
func (it *networkIterator) next() (Result, bool) {
	r := it.reader
	n := it.opts

	for len(it.nodes) > 0 {
		node := it.nodes[len(it.nodes)-1]
		it.nodes = it.nodes[:len(it.nodes)-1]

		for {
			if node.pointer == r.Metadata.NodeCount {
				if n.includeEmptyNetworks {
					return Result{
						ip:        mappedIP(node.ip),
						offset:    notFound,
						prefixLen: uint8(node.bit),
					}, true
				}
				break
			}
			// This skips IPv4 aliases without hardcoding the networks that the writer
			// currently aliases.
			if !n.includeAliasedNetworks && r.ipv4Start != 0 &&
				node.pointer == r.ipv4Start && !isInIPv4Subtree(node.ip) {
				break
			}

			if node.pointer > r.Metadata.NodeCount {
				offset, err := r.resolveDataPointer(node.pointer)

				// Check if we should skip empty values (only if no error)
				if err == nil && n.skipEmptyValues {
					var isEmpty bool
					isEmpty, err = r.decoder.IsEmptyValueAt(uint(offset))
					if err == nil && isEmpty {
						// Skip this empty value
						break
					}
				}

				return Result{
					reader:    r,
					ip:        mappedIP(node.ip),
					offset:    uint(offset),
					prefixLen: uint8(node.bit),
					err:       err,
				}, true
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

				// Fatal: the traversal cannot continue past a corrupt node.
				it.nodes = it.nodes[:0]
				return res, true
			}
			ipRight[node.bit>>3] |= 1 << (7 - (node.bit % 8))

			baseOffset := node.pointer * r.nodeOffsetMult
			leftPointer, rightPointer, err := readNodePairBySize(
				r.buffer,
				baseOffset,
				r.Metadata.RecordSize,
			)
			if err != nil {
				// Fatal: the traversal cannot continue past an unreadable node.
				it.nodes = it.nodes[:0]
				return Result{
					ip:        mappedIP(node.ip),
					prefixLen: uint8(node.bit),
					err:       err,
				}, true
			}

			node.bit++
			it.nodes = append(it.nodes, netNode{
				pointer: rightPointer,
				ip:      netip.AddrFrom16(ipRight),
				bit:     node.bit,
			})

			node.pointer = leftPointer
		}
	}
	runtime.KeepAlive(r)
	return Result{}, false
}

// resumePoint returns the normalized address and bit depth of the next node
// the traversal would visit. ok is false when the traversal is complete. The
// returned position is expressed purely in network space; it contains no node
// pointers or data-section offsets.
func (it *networkIterator) resumePoint() (netip.Addr, uint, bool) {
	if len(it.nodes) == 0 {
		return netip.Addr{}, 0, false
	}
	top := it.nodes[len(it.nodes)-1]
	return top.ip, top.bit, true
}

// resume rebuilds the pending-node stack so that the node at (ip, bit) is the
// next one visited. The stack of a depth-first traversal is fully determined
// by the path from the traversal root to that node: every left turn along the
// path leaves the corresponding right sibling pending. resume replays that
// path, re-reading the child pointers from the tree, so no internal pointer
// needs to be serialized.
func (it *networkIterator) resume(ip netip.Addr, bit uint) error {
	r := it.reader
	if len(it.nodes) != 1 {
		return errors.New("resume called on a traversal that has already started")
	}
	node := it.nodes[0]
	if bit < node.bit || bit > 128 {
		return fmt.Errorf(
			"resume position %s/%d is outside the traversal rooted at %s/%d",
			ip, bit, node.ip, node.bit,
		)
	}

	nodes := make([]netNode, 0, 64)
	for node.bit < bit {
		if node.pointer >= r.Metadata.NodeCount {
			return mmdberrors.NewInvalidDatabaseError(
				"resume position %s/%d does not match the search tree at %s/%d",
				ip, bit, node.ip, node.bit,
			)
		}

		baseOffset := node.pointer * r.nodeOffsetMult
		leftPointer, rightPointer, err := readNodePairBySize(
			r.buffer,
			baseOffset,
			r.Metadata.RecordSize,
		)
		if err != nil {
			return err
		}

		ipRight := node.ip.As16()
		if len(ipRight) <= int(node.bit>>3) {
			return mmdberrors.NewInvalidDatabaseError(
				"invalid search tree at %s/%d", node.ip, node.bit,
			)
		}
		ipRight[node.bit>>3] |= 1 << (7 - (node.bit % 8))
		right := netNode{
			pointer: rightPointer,
			ip:      netip.AddrFrom16(ipRight),
			bit:     node.bit + 1,
		}

		ipBytes := ip.As16()
		goesRight := ipBytes[node.bit>>3]>>(7-(node.bit%8))&1 == 1
		node.bit++
		if goesRight {
			node.ip = right.ip
			node.pointer = rightPointer
		} else {
			// The right sibling remains pending, exactly as in the
			// forward traversal.
			nodes = append(nodes, right)
			node.pointer = leftPointer
		}
	}

	if node.ip != ip {
		return fmt.Errorf(
			"resume position %s/%d is not contained in the traversal rooted at %s/%d",
			ip, bit, it.nodes[0].ip, it.nodes[0].bit,
		)
	}

	it.nodes = append(nodes, node)
	return nil
}

var ipv4SubtreeBoundary = netip.MustParseAddr("::255.255.255.255").Next()

func mappedIP(ip netip.Addr) netip.Addr {
	if isInIPv4Subtree(ip) {
		return v6ToV4(ip)
	}
	return ip
}

// isInIPv4Subtree returns true if the IP is in the database's IPv4 subtree.
func isInIPv4Subtree(ip netip.Addr) bool {
	return ip.Is4() || ip.Less(ipv4SubtreeBoundary)
}

// We store IPv4 addresses at ::/96 for unclear reasons.
func v4ToV16(ip netip.Addr) netip.Addr {
	b4 := ip.As4()
	return netip.AddrFrom16([16]byte{12: b4[0], 13: b4[1], 14: b4[2], 15: b4[3]})
}

// Converts an IPv4 address embedded in IPv6 to IPv4.
func v6ToV4(ip netip.Addr) netip.Addr {
	b := ip.As16()
	return netip.AddrFrom4([4]byte(b[12:]))
}
