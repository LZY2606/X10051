package maxminddb

import (
	"iter"
	"net/netip"
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

		w := newNetworkWalker(r, n)
		root, ok := w.prepareRoot(prefix, yield)
		if !ok {
			return
		}
		w.run([]netNode{root}, 0, yield)
	}
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
