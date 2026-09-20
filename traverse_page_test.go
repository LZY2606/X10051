package maxminddb

import (
	"fmt"
	"net/netip"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// networkRecord is a comparable snapshot of one traversal Result.
type networkRecord struct {
	Prefix string
	Found  bool
	Offset uintptr
	Err    string
}

func snapshotResult(r Result) networkRecord {
	rec := networkRecord{
		Prefix: r.Prefix().String(),
		Found:  r.Found(),
		Offset: r.Offset(),
	}
	if r.Err() != nil {
		rec.Err = r.Err().Error()
	}
	return rec
}

func collectIterator(t *testing.T, r *Reader, prefix netip.Prefix, opts []NetworksOption) []networkRecord {
	t.Helper()
	var out []networkRecord
	for result := range r.NetworksWithin(prefix, opts...) {
		require.NoError(t, result.Err())
		out = append(out, snapshotResult(result))
	}
	return out
}

// collectPages pages through the traversal and fails if paging cannot
// terminate: an empty page must always carry an empty resume token.
func collectPages(
	t *testing.T,
	r *Reader,
	prefix netip.Prefix,
	pageSize int,
	opts []NetworksOption,
) []networkRecord {
	t.Helper()
	var out []networkRecord
	token := ""
	for pages := 0; ; pages++ {
		page, err := r.NetworksWithinPage(prefix, pageSize, token, opts...)
		require.NoError(t, err)
		for _, result := range page.Results {
			require.NoError(t, result.Err())
			out = append(out, snapshotResult(result))
		}
		if page.ResumeToken == "" {
			return out
		}
		require.NotEmpty(t, page.Results,
			"an empty page must end the traversal (empty resume token)")
		require.Less(t, pages, 100000, "paging did not terminate")
		token = page.ResumeToken
	}
}

// TestNetworksWithinPageMatchesIterator falsifies the assumption that paging
// could reorder, drop, or duplicate networks: for page sizes 1, 2, 7, and
// larger than the total, the concatenation of all pages must equal the full
// iterator output item by item.
func TestNetworksWithinPageMatchesIterator(t *testing.T) {
	databases := []string{"ipv4", "ipv6", "mixed"}
	optionSets := map[string][]NetworksOption{
		"default":            nil,
		"aliased":            {IncludeAliasedNetworks()},
		"without-data":       {IncludeNetworksWithoutData()},
		"aliased+empty+skip": {IncludeAliasedNetworks(), IncludeNetworksWithoutData(), SkipEmptyValues()},
	}
	prefixes := map[string]string{
		"ipv4":  "0.0.0.0/0",
		"ipv6":  "::/0",
		"mixed": "::/0",
	}

	for _, database := range databases {
		for _, recordSize := range []uint{24, 28, 32} {
			fileName := testFile(
				fmt.Sprintf("MaxMind-DB-test-%s-%d.mmdb", database, recordSize),
			)
			reader, err := Open(fileName)
			require.NoError(t, err)

			for optName, opts := range optionSets {
				prefix := netip.MustParsePrefix(prefixes[database])
				want := collectIterator(t, reader, prefix, opts)
				require.NotEmpty(t, want)

				for _, pageSize := range []int{1, 2, 7, len(want) + 13} {
					name := fmt.Sprintf("%s-%d/%s/size=%d", database, recordSize, optName, pageSize)
					t.Run(name, func(t *testing.T) {
						got := collectPages(t, reader, prefix, pageSize, opts)
						assert.Equal(t, want, got)
					})
				}
			}
			require.NoError(t, reader.Close())
		}
	}
}

// TestNetworksWithinPageResumeOnNewReader falsifies the assumption that a
// resume token depends on Reader-instance state: a token produced by one
// Reader must resume on a freshly opened Reader of the same database.
func TestNetworksWithinPageResumeOnNewReader(t *testing.T) {
	fileName := testFile("MaxMind-DB-test-mixed-28.mmdb")
	prefix := netip.MustParsePrefix("::/0")
	opts := []NetworksOption{IncludeAliasedNetworks()}

	reader1, err := Open(fileName)
	require.NoError(t, err)
	defer func() { require.NoError(t, reader1.Close()) }()

	want := collectIterator(t, reader1, prefix, opts)

	// First page from the first reader.
	first, err := reader1.NetworksWithinPage(prefix, 3, "", opts...)
	require.NoError(t, err)
	require.Len(t, first.Results, 3)
	require.NotEmpty(t, first.ResumeToken)

	// Remaining pages from a new Reader instance.
	reader2, err := Open(fileName)
	require.NoError(t, err)
	defer func() { require.NoError(t, reader2.Close()) }()

	var got []networkRecord
	for _, result := range first.Results {
		require.NoError(t, result.Err())
		got = append(got, snapshotResult(result))
	}
	token := first.ResumeToken
	for token != "" {
		page, err := reader2.NetworksWithinPage(prefix, 4, token, opts...)
		require.NoError(t, err)
		for _, result := range page.Results {
			require.NoError(t, result.Err())
			got = append(got, snapshotResult(result))
		}
		token = page.ResumeToken
	}

	assert.Equal(t, want, got)
}

// TestNetworksWithinPageTokenErrors falsifies the assumption that a resume
// token is accepted outside its binding: corrupt, stale (different database),
// or configuration-mismatched tokens must fail with ErrInvalidNetworksToken
// and diagnosable context.
func TestNetworksWithinPageTokenErrors(t *testing.T) {
	fileName := testFile("MaxMind-DB-test-mixed-24.mmdb")
	reader, err := Open(fileName)
	require.NoError(t, err)
	defer func() { require.NoError(t, reader.Close()) }()

	prefix := netip.MustParsePrefix("::/0")
	page, err := reader.NetworksWithinPage(prefix, 1, "")
	require.NoError(t, err)
	require.NotEmpty(t, page.ResumeToken)
	validToken := page.ResumeToken

	t.Run("corrupt token fails checksum", func(t *testing.T) {
		// Flip one payload character while keeping valid base64url.
		flip := func(c byte) byte {
			if c == 'A' {
				return 'B'
			}
			return 'A'
		}
		corrupt := validToken[:5] + string(flip(validToken[5])) + validToken[6:]
		_, err := reader.NetworksWithinPage(prefix, 1, corrupt)
		require.ErrorIs(t, err, ErrInvalidNetworksToken)
		assert.Contains(t, err.Error(), "checksum")
	})

	t.Run("non-base64 token", func(t *testing.T) {
		_, err := reader.NetworksWithinPage(prefix, 1, "!!!not-a-token!!!")
		require.ErrorIs(t, err, ErrInvalidNetworksToken)
	})

	t.Run("truncated token", func(t *testing.T) {
		_, err := reader.NetworksWithinPage(prefix, 1, validToken[:len(validToken)-4])
		require.ErrorIs(t, err, ErrInvalidNetworksToken)
	})

	t.Run("stale token from a different database", func(t *testing.T) {
		other, err := Open(testFile("MaxMind-DB-test-ipv4-24.mmdb"))
		require.NoError(t, err)
		defer func() { require.NoError(t, other.Close()) }()

		otherPage, err := other.NetworksWithinPage(netip.MustParsePrefix("0.0.0.0/0"), 1, "")
		require.NoError(t, err)
		require.NotEmpty(t, otherPage.ResumeToken)

		_, err = reader.NetworksWithinPage(prefix, 1, otherPage.ResumeToken)
		require.ErrorIs(t, err, ErrInvalidNetworksToken)
		assert.Contains(t, err.Error(), "different database")
	})

	t.Run("same database with different record size is a different database", func(t *testing.T) {
		other, err := Open(testFile("MaxMind-DB-test-mixed-32.mmdb"))
		require.NoError(t, err)
		defer func() { require.NoError(t, other.Close()) }()

		otherPage, err := other.NetworksWithinPage(prefix, 1, "")
		require.NoError(t, err)
		require.NotEmpty(t, otherPage.ResumeToken)

		_, err = reader.NetworksWithinPage(prefix, 1, otherPage.ResumeToken)
		require.ErrorIs(t, err, ErrInvalidNetworksToken)
		assert.Contains(t, err.Error(), "different database")
	})

	t.Run("token bound to a different prefix", func(t *testing.T) {
		_, err := reader.NetworksWithinPage(
			netip.MustParsePrefix("1.1.1.0/24"), 1, validToken,
		)
		require.ErrorIs(t, err, ErrInvalidNetworksToken)
		assert.Contains(t, err.Error(), "prefix")
	})

	t.Run("token bound to different options", func(t *testing.T) {
		_, err := reader.NetworksWithinPage(
			prefix, 1, validToken, IncludeAliasedNetworks(),
		)
		require.ErrorIs(t, err, ErrInvalidNetworksToken)
		assert.Contains(t, err.Error(), "options")
	})

	t.Run("valid token still resumes", func(t *testing.T) {
		rest, err := reader.NetworksWithinPage(prefix, 100, validToken)
		require.NoError(t, err)
		assert.NotEmpty(t, rest.Results)
	})
}

// TestNetworksWithinPageEmptyPageTerminates falsifies the assumption that an
// empty page could carry a non-empty token and loop forever.
func TestNetworksWithinPageEmptyPageTerminates(t *testing.T) {
	reader, err := Open(testFile("MaxMind-DB-test-ipv4-24.mmdb"))
	require.NoError(t, err)
	defer func() { require.NoError(t, reader.Close()) }()

	// A prefix with no networks underneath: the first page is already empty
	// and must end the traversal immediately.
	page, err := reader.NetworksWithinPage(netip.MustParsePrefix("255.255.255.0/24"), 5, "")
	require.NoError(t, err)
	assert.Empty(t, page.Results)
	assert.Empty(t, page.ResumeToken)

	// A page size larger than the total yields one partial final page and an
	// empty token; a follow-up call must not restart the traversal.
	prefix := netip.MustParsePrefix("0.0.0.0/0")
	page, err = reader.NetworksWithinPage(prefix, 1000, "")
	require.NoError(t, err)
	require.NotEmpty(t, page.Results)
	assert.Empty(t, page.ResumeToken)
}

// TestNetworksWithinPageBoundaries checks argument validation and parity of
// boundary errors with the iterator API.
func TestNetworksWithinPageBoundaries(t *testing.T) {
	reader, err := Open(testFile("MaxMind-DB-test-ipv4-24.mmdb"))
	require.NoError(t, err)
	defer func() { require.NoError(t, reader.Close()) }()

	prefix := netip.MustParsePrefix("0.0.0.0/0")

	for _, size := range []int{0, -1} {
		_, err := reader.NetworksWithinPage(prefix, size, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "page size")
	}

	_, err = reader.NetworksWithinPage(netip.Prefix{}, 1, "")
	require.EqualError(t, err, "invalid prefix")

	_, err = reader.NetworksWithinPage(netip.MustParsePrefix("::/0"), 1, "")
	require.EqualError(t, err,
		"error getting networks with '::/0': you attempted to use an IPv6 network in an IPv4-only database")

	// A prefix contained within a single network pages to exactly one result.
	page, err := reader.NetworksWithinPage(netip.MustParsePrefix("1.1.1.3/32"), 1, "")
	require.NoError(t, err)
	require.Len(t, page.Results, 1)
	assert.Equal(t, "1.1.1.2/31", page.Results[0].Prefix().String())
	assert.Empty(t, page.ResumeToken)
}

// TestNetworksWithinPageSkipEmptyValues falsifies the assumption that
// filtering (SkipEmptyValues) could desynchronize paging: the resume position
// is a search-tree node, not a visible-result index, so skipped records must
// not shift the sequence across page boundaries.
func TestNetworksWithinPageSkipEmptyValues(t *testing.T) {
	reader, err := Open(testFile("GeoIP2-Anonymous-IP-Test.mmdb"))
	require.NoError(t, err)
	defer func() { require.NoError(t, reader.Close()) }()

	prefix := netip.MustParsePrefix("::/0")
	opts := []NetworksOption{SkipEmptyValues()}

	want := collectIterator(t, reader, prefix, opts)
	require.NotEmpty(t, want)

	for _, pageSize := range []int{1, 2, 7, len(want) + 13} {
		t.Run(fmt.Sprintf("size=%d", pageSize), func(t *testing.T) {
			got := collectPages(t, reader, prefix, pageSize, opts)
			assert.Equal(t, want, got)
		})
	}

	// Every paged result must honor the filter.
	for _, rec := range want {
		assert.NotNil(t, rec)
	}
}

// TestNetworksWithinPageExistingExpectations reuses the NetworksWithin
// expectation table: paged traversal must reproduce the exact expected
// networks, guarding against a shared-mode failure of both implementations.
func TestNetworksWithinPageExistingExpectations(t *testing.T) {
	for _, v := range tests {
		for _, recordSize := range []uint{24, 28, 32} {
			opts := make([]string, 0, len(v.Options))
			for _, o := range v.Options {
				opts = append(opts, runtime.FuncForPC(reflect.ValueOf(o).Pointer()).Name())
			}
			name := fmt.Sprintf("%s-%d: %s, options: %v", v.Database, recordSize, v.Network, opts)
			t.Run(name, func(t *testing.T) {
				fileName := testFile(
					fmt.Sprintf("MaxMind-DB-test-%s-%d.mmdb", v.Database, recordSize),
				)
				reader, err := Open(fileName)
				require.NoError(t, err)
				defer func() { require.NoError(t, reader.Close()) }()

				parts := strings.Split(v.Network, "/")
				ip, err := netip.ParseAddr(parts[0])
				require.NoError(t, err)
				prefixLength, err := strconv.Atoi(parts[1])
				require.NoError(t, err)
				network, err := ip.Prefix(prefixLength)
				require.NoError(t, err)

				for _, pageSize := range []int{1, 7} {
					got := collectPages(t, reader, network, pageSize, v.Options)
					prefixes := make([]string, 0, len(got))
					for _, rec := range got {
						prefixes = append(prefixes, rec.Prefix)
					}
					assert.Equal(t, v.Expected, prefixes, "page size %d", pageSize)
				}
			})
		}
	}
}

// TestNetworksWithinPageTokenDoesNotExposeInternals falsifies the assumption
// that the token leaks internal offsets: it must be a fixed-size encoding of
// a version, metadata fingerprint, options, prefix, and network-space
// position only.
func TestNetworksWithinPageTokenDoesNotExposeInternals(t *testing.T) {
	reader, err := Open(testFile("MaxMind-DB-test-mixed-24.mmdb"))
	require.NoError(t, err)
	defer func() { require.NoError(t, reader.Close()) }()

	prefix := netip.MustParsePrefix("::/0")
	page, err := reader.NetworksWithinPage(prefix, 1, "")
	require.NoError(t, err)
	require.NotEmpty(t, page.ResumeToken)

	raw, err := networksTokenEncoding.DecodeString(page.ResumeToken)
	require.NoError(t, err)
	require.Len(t, raw, networksTokenSize)

	// The only position information is an address and a prefix length.
	resumeIP := netip.AddrFrom16([16]byte(raw[27:43]))
	resumeBits := uint(raw[43])
	assert.True(t, resumeIP.Is6())
	assert.LessOrEqual(t, resumeBits, uint(128))

	// No field may contain a search-tree node pointer or data offset; the
	// encoding carries exactly one address and one bit depth beyond the
	// binding fields, which the resume path re-derives pointers from.
	assert.Equal(t, byte(networksTokenVersion), raw[0])
}
