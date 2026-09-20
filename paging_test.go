package maxminddb

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// collectIter gathers every visible network (prefix strings and data offsets)
// from the plain iterator in its canonical order. It is the reference
// sequence that paged traversal must reproduce item-for-item.
func collectIter(
	t *testing.T,
	r *Reader,
	prefix netip.Prefix,
	options ...NetworksOption,
) []string {
	t.Helper()
	var got []string
	for result := range r.NetworksWithin(prefix, options...) {
		require.NoError(t, result.Err())
		got = append(got, resultKey(result))
	}
	return got
}

// resultKey identifies an emitted network including whether it carries data.
// Two results share a key only when they are the same traversal item.
func resultKey(result Result) string {
	if result.Found() {
		return result.Prefix().String() + fmt.Sprintf("#%d", result.Offset())
	}
	return result.Prefix().String() + "#empty"
}

func pageAll(
	t *testing.T,
	r *Reader,
	prefix netip.Prefix,
	pageSize int,
	options ...NetworksOption,
) ([]string, *NetworkCursor) {
	t.Helper()
	var got []string
	var cursor *NetworkCursor
	for {
		page, err := r.NetworksWithinPage(cursor, prefix, pageSize, options...)
		require.NoError(t, err)
		for _, result := range page.Results {
			require.NoError(t, result.Err())
			got = append(got, resultKey(result))
		}
		if page.Next == nil {
			return got, cursor
		}
		// A cursor must never repeat between consecutive pages; otherwise a
		// caller would make no progress and could loop forever.
		if cursor != nil {
			require.NotEqual(t, cursor.String(), page.Next.String(),
				"cursor did not advance")
		}
		cursor = page.Next
	}
}

// TestPagingMatchesIteratorForEverySize is the core determinism acceptance
// test: for page sizes 1, 2, 7, and one larger than the total, the
// concatenation of pages must equal the full iterator item-for-item. It
// falsifies the assumptions that (a) paging changes traversal order and (b)
// only some page sizes align with tree structure.
func TestPagingMatchesIteratorForEverySize(t *testing.T) {
	cases := []struct {
		name    string
		dbFile  string
		prefix  string
		options []NetworksOption
	}{
		{"ipv4/0", "MaxMind-DB-test-ipv4-24.mmdb", "0.0.0.0/0", nil},
		{"ipv4/0-28", "MaxMind-DB-test-ipv4-28.mmdb", "0.0.0.0/0", nil},
		{"ipv4/0-32", "MaxMind-DB-test-ipv4-32.mmdb", "0.0.0.0/0", nil},
		{"ipv6/0", "MaxMind-DB-test-ipv6-24.mmdb", "::/0", nil},
		{"ipv6/0-28", "MaxMind-DB-test-ipv6-28.mmdb", "::/0", nil},
		{"mixed-aliases", "MaxMind-DB-test-mixed-24.mmdb", "::/0",
			[]NetworksOption{IncludeAliasedNetworks()}},
		{"mixed-no-aliases", "MaxMind-DB-test-mixed-28.mmdb", "::/0", nil},
		{"subtree", "MaxMind-DB-test-mixed-32.mmdb", "1.0.0.0/8",
			[]NetworksOption{IncludeNetworksWithoutData()}},
		{"skip-empty", "GeoIP2-Anonymous-IP-Test.mmdb", "0.0.0.0/0",
			[]NetworksOption{SkipEmptyValues()}},
		{"geoip-country", "GeoIP2-Country-Test.mmdb", "81.2.69.128/26", nil},
		{"empty-region", "MaxMind-DB-test-ipv4-24.mmdb", "255.255.255.0/24", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Open(testFile(tc.dbFile))
			require.NoError(t, err)
			defer func() { require.NoError(t, r.Close()) }()

			prefix := netip.MustParsePrefix(tc.prefix)
			want := collectIter(t, r, prefix, tc.options...)

			for _, pageSize := range []int{1, 2, 7, len(want) + 5} {
				t.Run(fmt.Sprintf("size-%d", pageSize), func(t *testing.T) {
					got, _ := pageAll(t, r, prefix, pageSize, tc.options...)
					require.Equal(t, want, got)
				})
			}
		})
	}
}

// TestPagingBoundariesAndSizes checks the per-page size contract: every
// non-final page has exactly pageSize visible results, the final page holds
// the remainder, and a page size larger than the total yields a single page.
func TestPagingBoundariesAndSizes(t *testing.T) {
	r, err := Open(testFile("MaxMind-DB-test-ipv4-24.mmdb"))
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()

	prefix := netip.MustParsePrefix("0.0.0.0/0")
	want := collectIter(t, r, prefix)
	require.NotEmpty(t, want)

	for _, pageSize := range []int{1, 2, 3, 7, len(want), len(want) + 10} {
		var cursor *NetworkCursor
		var pageNo int
		var total int
		for {
			page, err := r.NetworksWithinPage(cursor, prefix, pageSize)
			require.NoError(t, err)
			pageNo++
			total += len(page.Results)

			if page.Next == nil {
				require.LessOrEqual(t, len(page.Results), pageSize)
				break
			}
			require.Len(t, page.Results, pageSize,
				"non-final page %d must be full", pageNo)
			cursor = page.Next
		}
		require.Len(t, want, total, "page size %d", pageSize)
	}
}

// TestPagingEmptyRegionTerminates verifies that a prefix containing no
// visible networks terminates on the first page with a nil cursor instead of
// handing back a cursor that would drive an empty-page loop.
func TestPagingEmptyRegionTerminates(t *testing.T) {
	r, err := Open(testFile("MaxMind-DB-test-ipv4-24.mmdb"))
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()

	page, err := r.NetworksWithinPage(
		nil,
		netip.MustParsePrefix("255.255.255.0/24"),
		2,
	)
	require.NoError(t, err)
	require.Empty(t, page.Results)
	require.Nil(t, page.Next)
}

// TestPagingContainingPrefixReturnsOne matches the NetworksWithin guarantee
// that a prefix contained in a database network yields that one network.
func TestPagingContainingPrefixReturnsOne(t *testing.T) {
	r, err := Open(testFile("MaxMind-DB-test-ipv4-24.mmdb"))
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()

	got, _ := pageAll(t, r, netip.MustParsePrefix("1.1.1.2/32"), 7)
	require.Len(t, got, 1)
	require.True(t, strings.HasPrefix(got[0], "1.1.1.2/31#"), got[0])
}

// TestPagingResumeOnFreshReader verifies the headline capability: a cursor
// serialized to a string resumes on a brand-new Reader opened independently,
// and the stitched sequence still equals the full iterator. This falsifies
// the assumption that resumption secretly depends on in-memory state.
func TestPagingResumeOnFreshReader(t *testing.T) {
	path := testFile("MaxMind-DB-test-mixed-28.mmdb")
	prefix := netip.MustParsePrefix("::/0")
	options := []NetworksOption{IncludeAliasedNetworks()}

	r0, err := Open(path)
	require.NoError(t, err)
	want := collectIter(t, r0, prefix, options...)
	require.NoError(t, r0.Close())

	var got []string
	var token string
	pageSize := 1
	first := true
	for {
		r, err := Open(path)
		require.NoError(t, err)

		var cursor *NetworkCursor
		if !first {
			cursor, err = ParseNetworkCursor(token)
			require.NoError(t, err)
		}

		page, err := r.NetworksWithinPage(cursor, prefix, pageSize, options...)
		require.NoError(t, err)
		for _, result := range page.Results {
			require.NoError(t, result.Err())
			got = append(got, resultKey(result))
		}
		require.NoError(t, r.Close())

		if page.Next == nil {
			break
		}
		token = page.Next.String()
		first = false
		pageSize = 1 + len(got)%3
	}
	require.Equal(t, want, got)
}

// TestPagingCursorRejectsCorruption mutates tokens in every plausible way
// and asserts a clear ErrCursorCorrupt. This falsifies the assumption that
// parsing is lenient about structure or integrity.
func TestPagingCursorRejectsCorruption(t *testing.T) {
	r, cursor := firstCursor(t, "MaxMind-DB-test-ipv4-24.mmdb",
		netip.MustParsePrefix("0.0.0.0/0"), 1)
	defer func() { require.NoError(t, r.Close()) }()

	token := cursor.String()

	t.Run("garbage", func(t *testing.T) {
		_, err := ParseNetworkCursor("not a cursor")
		require.ErrorIs(t, err, ErrCursorCorrupt)
	})
	t.Run("empty", func(t *testing.T) {
		_, err := ParseNetworkCursor("")
		require.ErrorIs(t, err, ErrCursorCorrupt)
	})
	t.Run("single segment", func(t *testing.T) {
		parts := strings.Split(token, ".")
		_, err := ParseNetworkCursor(parts[0])
		require.ErrorIs(t, err, ErrCursorCorrupt)
	})
	t.Run("flipped payload bit", func(t *testing.T) {
		bad := flipBase64Char(t, token, 0)
		_, err := ParseNetworkCursor(bad)
		require.ErrorIs(t, err, ErrCursorCorrupt)
	})
	t.Run("flipped mac bit", func(t *testing.T) {
		dot := strings.IndexByte(token, '.')
		bad := flipBase64Char(t, token, dot+1)
		parsed, perr := ParseNetworkCursor(bad)
		// Either the MAC fails base64/HMAC verification at parse time...
		if perr == nil {
			// ...or at resume time.
			_, err := r.NetworksWithinPage(parsed,
				netip.MustParsePrefix("0.0.0.0/0"), 1)
			require.ErrorIs(t, err, ErrCursorCorrupt)
		} else {
			require.ErrorIs(t, perr, ErrCursorCorrupt)
		}
	})
	t.Run("truncated payload", func(t *testing.T) {
		parts := strings.Split(token, ".")
		payload, err := base64RawDecode(parts[0])
		require.NoError(t, err)
		bad := encodeRawParts(payload[:len(payload)-2], mustBase64Raw(t, parts[1]))
		_, err = ParseNetworkCursor(bad)
		require.ErrorIs(t, err, ErrCursorCorrupt)
	})
	t.Run("zero value cursor", func(t *testing.T) {
		var zero NetworkCursor
		_, err := r.NetworksWithinPage(&zero,
			netip.MustParsePrefix("0.0.0.0/0"), 1)
		require.ErrorIs(t, err, ErrCursorCorrupt)
	})
}

func firstCursor(
	t *testing.T,
	dbFile string,
	prefix netip.Prefix,
	pageSize int,
	options ...NetworksOption,
) (*Reader, *NetworkCursor) {
	t.Helper()
	r, err := Open(testFile(dbFile))
	require.NoError(t, err)
	page, err := r.NetworksWithinPage(nil, prefix, pageSize, options...)
	require.NoError(t, err)
	require.NotNil(t, page.Next, "test database must have more than one page")
	return r, page.Next
}

func base64RawDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func mustBase64Raw(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}

func encodeRawParts(payload, mac []byte) string {
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac)
}

// flipBase64Char flips one bit in the base64 alphabet character at index idx.
func flipBase64Char(t *testing.T, token string, idx int) string {
	t.Helper()
	b := []byte(token)
	require.NotEqual(t, '.', b[idx])
	ch := b[idx]
	var replacement byte
	for _, cand := range []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") {
		if cand != ch {
			replacement = cand
			break
		}
	}
	require.NotZero(t, replacement)
	b[idx] = replacement
	return string(b)
}

// TestPagingCursorRejectsOtherDatabase replays a cursor on a different
// database (different node count / tree shape). It falsifies the assumption
// that a token built solely from the prefix could be replayed anywhere.
func TestPagingCursorRejectsOtherDatabase(t *testing.T) {
	src, cursor := firstCursor(t, "MaxMind-DB-test-ipv4-24.mmdb",
		netip.MustParsePrefix("0.0.0.0/0"), 1)
	token := cursor.String()
	require.NoError(t, src.Close())

	other, err := Open(testFile("MaxMind-DB-test-ipv4-28.mmdb"))
	require.NoError(t, err)
	defer func() { require.NoError(t, other.Close()) }()

	resumed, err := ParseNetworkCursor(token)
	require.NoError(t, err)
	_, err = other.NetworksWithinPage(resumed,
		netip.MustParsePrefix("0.0.0.0/0"), 1)
	require.ErrorIs(t, err, ErrCursorWrongDatabase)
}

// TestPagingCursorRejectsStaleDatabase replays a cursor after the file's
// metadata changed, simulating a database update. The BuildEpoch is part of
// the fingerprint, so an updated build invalidates old cursors.
func TestPagingCursorStaleAfterUpdate(t *testing.T) {
	original, err := os.ReadFile(testFile("GeoIP2-Country-Test.mmdb"))
	require.NoError(t, err)

	r1, err := OpenBytes(original)
	require.NoError(t, err)
	page, err := r1.NetworksWithinPage(nil, netip.MustParsePrefix("::/0"), 1)
	require.NoError(t, err)
	require.NotNil(t, page.Next)
	token := page.Next.String()
	require.NoError(t, r1.Close())

	updated := buildMetadataVariant(t, original, "GeoIP2-Xountry")
	r2, err := OpenBytes(updated)
	require.NoError(t, err)
	defer func() { require.NoError(t, r2.Close()) }()

	cursor, err := ParseNetworkCursor(token)
	require.NoError(t, err)
	_, err = r2.NetworksWithinPage(cursor, netip.MustParsePrefix("::/0"), 1)
	require.ErrorIs(t, err, ErrCursorWrongDatabase)
}

// TestPagingCursorRejectsConfigMismatch verifies that prefix and every
// iterator option is part of the binding.
func TestPagingCursorRejectsConfigMismatch(t *testing.T) {
	r, cursor := firstCursor(t, "MaxMind-DB-test-mixed-24.mmdb",
		netip.MustParsePrefix("::/0"), 1, IncludeAliasedNetworks())
	defer func() { require.NoError(t, r.Close()) }()
	token := cursor.String()

	t.Run("different prefix", func(t *testing.T) {
		c, err := ParseNetworkCursor(token)
		require.NoError(t, err)
		_, err = r.NetworksWithinPage(c, netip.MustParsePrefix("2001::/16"),
			1, IncludeAliasedNetworks())
		require.ErrorIs(t, err, ErrCursorPrefixMismatch)
	})
	t.Run("dropped option", func(t *testing.T) {
		c, err := ParseNetworkCursor(token)
		require.NoError(t, err)
		_, err = r.NetworksWithinPage(c, netip.MustParsePrefix("::/0"), 1)
		require.ErrorIs(t, err, ErrCursorOptionsMismatch)
	})
	t.Run("added option", func(t *testing.T) {
		c, err := ParseNetworkCursor(token)
		require.NoError(t, err)
		_, err = r.NetworksWithinPage(c, netip.MustParsePrefix("::/0"), 1,
			IncludeAliasedNetworks(), SkipEmptyValues())
		require.ErrorIs(t, err, ErrCursorOptionsMismatch)
	})
}

// TestPagingInvalidPageSize guards the API against size zero and negatives.
func TestPagingInvalidPageSize(t *testing.T) {
	r, err := Open(testFile("MaxMind-DB-test-ipv4-24.mmdb"))
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()

	for _, size := range []int{0, -1} {
		_, err := r.NetworksWithinPage(nil,
			netip.MustParsePrefix("0.0.0.0/0"), size)
		require.ErrorIs(t, err, ErrPageSize)
	}
}

// TestPagingInvalidPrefixDeliversResultError matches NetworksWithin: prefix
// problems on the first page arrive as a Result error, preserving the old
// error text and classification.
func TestPagingInvalidPrefixDeliversResultError(t *testing.T) {
	r, err := Open(testFile("MaxMind-DB-test-ipv4-24.mmdb"))
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()

	page, err := r.NetworksWithinPage(nil, netip.Prefix{}, 2)
	require.NoError(t, err)
	require.Len(t, page.Results, 1)
	require.EqualError(t, page.Results[0].Err(), "invalid prefix")
	require.Nil(t, page.Next)

	page, err = r.NetworksWithinPage(nil,
		netip.MustParsePrefix("::1/128"), 2)
	require.NoError(t, err)
	require.Len(t, page.Results, 1)
	require.ErrorContains(t, page.Results[0].Err(),
		"you attempted to use an IPv6 network in an IPv4-only database")
	require.Nil(t, page.Next)
}

// buildMetadataVariant returns a copy of buffer whose database_type metadata
// string is replaced in place with replacement (which must have the same
// byte length). The tree is unchanged; this models a metadata-level database
// update that must invalidate old cursors even against an identical tree.
func buildMetadataVariant(t *testing.T, buffer []byte, replacement string) []byte {
	t.Helper()
	markerStart := bytes.LastIndex(buffer, metadataStartMarker)
	require.NotEqual(t, -1, markerStart)
	meta := buffer[markerStart+len(metadataStartMarker):]

	const oldType = "GeoIP2-Country"
	idx := bytes.Index(meta, []byte(oldType))
	require.NotEqual(t, -1, idx)
	require.Len(t, replacement, len(oldType))

	out := append([]byte(nil), buffer...)
	copy(out[markerStart+len(metadataStartMarker)+idx:], []byte(replacement))
	return out
}

// TestPagingCursorTokenIsOpaqueAndStable verifies the token contract:
//   - equal continuation positions produce identical tokens (deterministic);
//   - the token never embeds search-tree pointers or data-section offsets.
//
// This falsifies the assumption that resume secretly depends on internal
// pointer offsets being serialized.
func TestPagingCursorTokenIsOpaqueAndStable(t *testing.T) {
	r, err := Open(testFile("MaxMind-DB-test-mixed-24.mmdb"))
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()

	prefix := netip.MustParsePrefix("::/0")
	takeFirst := func() *NetworkCursor {
		page, err := r.NetworksWithinPage(nil, prefix, 3,
			IncludeAliasedNetworks())
		require.NoError(t, err)
		require.NotNil(t, page.Next)
		return page.Next
	}

	c1 := takeFirst()
	c2 := takeFirst()
	require.Equal(t, c1.String(), c2.String(),
		"token for an identical position must be deterministic")

	token := c1.String()
	for _, result := range collectFirstPageResults(t, r, prefix, 3,
		IncludeAliasedNetworks()) {
		// Data offsets must not appear verbatim in the token.
		require.NotContains(t, token,
			fmt.Sprintf("%d", result.Offset()))
	}

	// The only readable text in the token must be from the bound prefix
	// representation; base64 segments do not contain dots besides the single
	// separator.
	require.Equal(t, 1, strings.Count(token, "."))
}

func collectFirstPageResults(
	t *testing.T,
	r *Reader,
	prefix netip.Prefix,
	pageSize int,
	options ...NetworksOption,
) []Result {
	t.Helper()
	page, err := r.NetworksWithinPage(nil, prefix, pageSize, options...)
	require.NoError(t, err)
	return page.Results
}

// TestPagingCursorTextRoundTrip exercises encoding.TextMarshaler and
// encoding.TextUnmarshaler, the JSON-friendly interface.
func TestPagingCursorTextRoundTrip(t *testing.T) {
	r, cursor := firstCursor(t, "MaxMind-DB-test-ipv6-24.mmdb",
		netip.MustParsePrefix("::/0"), 1)
	defer func() { require.NoError(t, r.Close()) }()

	text, err := cursor.MarshalText()
	require.NoError(t, err)
	require.NotEmpty(t, text)

	var resumed NetworkCursor
	require.NoError(t, resumed.UnmarshalText(text))
	require.Equal(t, cursor.String(), resumed.String())
	require.True(t, resumed.Prefix().IsValid())
}

// TestPagingIPv4AliasResume is the most dangerous traversal regression case:
// in a mixed database the IPv4 subtree is reachable both natively (::ffff
// aliases and the writer's 2001::/32, 2002::/16 aliases) and through the
// ::/96 subtree. When IncludeAliasedNetworks is off, alias frames must be
// pruned during DFS; when it is on, they must be retained. A continuation
// stack that straddles this boundary can only resume correctly if frames are
// reconstructed by path and re-evaluated against the alias rule. We assert
// paging with size 1 reproduces the exact alias and non-alias sequences.
func TestPagingIPv4AliasResume(t *testing.T) {
	for _, options := range [][]NetworksOption{
		nil,
		{IncludeAliasedNetworks()},
	} {
		r, err := Open(testFile("MaxMind-DB-test-mixed-32.mmdb"))
		require.NoError(t, err)

		prefix := netip.MustParsePrefix("::/0")
		want := collectIter(t, r, prefix, options...)
		got, _ := pageAll(t, r, prefix, 1, options...)
		require.Equal(t, want, got)
		require.NoError(t, r.Close())
	}
}

// TestPagingSkipEmptyValuesNeverLoops drives the case where whole tree
// regions emit nothing: with SkipEmptyValues, a page-size-1 traversal must
// still terminate and match the filtered iterator, and intermediate pages
// must never resurface the same cursor.
func TestPagingSkipEmptyValuesNeverLoops(t *testing.T) {
	r, err := Open(testFile("GeoIP2-Anonymous-IP-Test.mmdb"))
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()

	prefix := netip.MustParsePrefix("0.0.0.0/0")
	want := collectIter(t, r, prefix, SkipEmptyValues())
	got, _ := pageAll(t, r, prefix, 1, SkipEmptyValues())
	require.Equal(t, want, got)
}

// TestPagingIncludeEmptyNetworksResumes exercises the empty-network branch
// (pointer == NodeCount, offset notFound) across resume boundaries, since an
// empty leaf that lands exactly at a page boundary must not be duplicated or
// lost.
func TestPagingIncludeEmptyNetworksResumes(t *testing.T) {
	r, err := Open(testFile("MaxMind-DB-test-mixed-24.mmdb"))
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()

	prefix := netip.MustParsePrefix("1.0.0.0/8")
	want := collectIter(t, r, prefix, IncludeNetworksWithoutData())
	for _, size := range []int{1, 2, 7} {
		got, _ := pageAll(t, r, prefix, size, IncludeNetworksWithoutData())
		require.Equal(t, want, got, "size %d", size)
	}
}

// TestPagingResumeRejectsClosedDatabase documents that a closed Reader
// returns a direct error rather than panicking.
func TestPagingResumeRejectsClosedDatabase(t *testing.T) {
	r, err := Open(testFile("MaxMind-DB-test-ipv4-24.mmdb"))
	require.NoError(t, err)
	page, err := r.NetworksWithinPage(nil,
		netip.MustParsePrefix("0.0.0.0/0"), 1)
	require.NoError(t, err)
	require.NotNil(t, page.Next)
	require.NoError(t, r.Close())

	_, err = r.NetworksWithinPage(page.Next,
		netip.MustParsePrefix("0.0.0.0/0"), 1)
	require.ErrorContains(t, err, "closed database")
}

// TestPagingCursorPrefixAccessorExposesBoundPrefix lets callers diagnose
// which prefix a cursor belongs to without parsing the token themselves.
func TestPagingCursorPrefixAccessorExposesBoundPrefix(t *testing.T) {
	r, cursor := firstCursor(t, "MaxMind-DB-test-ipv4-24.mmdb",
		netip.MustParsePrefix("1.1.1.0/24"), 1)
	defer func() { require.NoError(t, r.Close()) }()
	require.Equal(t, "1.1.1.0/24", cursor.Prefix().String())
}

// TestPagingBrokenSearchTreeDeliversResultError matches the iterator: a
// corrupt tree reached mid-walk surfaces as the final Result error and ends
// the traversal instead of looping or returning a dangling cursor.
func TestPagingBrokenSearchTreeDeliversResultError(t *testing.T) {
	r, err := Open(testFile("MaxMind-DB-test-broken-search-tree-24.mmdb"))
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()

	prefix := netip.MustParsePrefix("0.0.0.0/0")
	var cursor *NetworkCursor
	var last Result
	pages := 0
	for {
		page, err := r.NetworksWithinPage(cursor, prefix, 1)
		require.NoError(t, err)
		pages++
		for _, res := range page.Results {
			last = res
		}
		if page.Next == nil {
			break
		}
		cursor = page.Next
		require.Less(t, pages, 1000, "corrupt tree must terminate paging")
	}
	require.ErrorContains(t, last.Err(), "invalid search tree at")
}

// TestPagingConcurrentResume exercises concurrent paged traversals that
// resume the same serialized cursor on independent goroutines, mirroring the
// Reader thread-safety guarantee.
func TestPagingConcurrentResume(t *testing.T) {
	r, cursor := firstCursor(t, "MaxMind-DB-test-mixed-24.mmdb",
		netip.MustParsePrefix("::/0"), 2, IncludeAliasedNetworks())
	token := cursor.String()
	require.NoError(t, r.Close())

	const goroutines = 8
	errCh := make(chan error, goroutines)
	for range goroutines {
		go func() {
			db, err := Open(testFile("MaxMind-DB-test-mixed-24.mmdb"))
			if err != nil {
				errCh <- err
				return
			}
			defer func() { _ = db.Close() }()

			c, err := ParseNetworkCursor(token)
			if err != nil {
				errCh <- err
				return
			}
			page, err := db.NetworksWithinPage(c,
				netip.MustParsePrefix("::/0"), 2, IncludeAliasedNetworks())
			if err != nil {
				errCh <- err
				return
			}
			for _, res := range page.Results {
				if res.Err() != nil {
					errCh <- res.Err()
					return
				}
			}
			errCh <- nil
		}()
	}
	for range goroutines {
		require.NoError(t, <-errCh)
	}
}

// TestPagingIPv4NonRootPrefixRoundTrip specifically guards encoding of an
// IPv4 prefix shorter than /32: its 16-byte storage form carries 96 leading
// zeros that must be masked relative to 96+bits, not bits. An earlier
// implementation rejected these tokens as having host bits set.
func TestPagingIPv4NonRootPrefixRoundTrip(t *testing.T) {
	r, err := Open(testFile("MaxMind-DB-test-mixed-24.mmdb"))
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()

	for _, prefix := range []string{
		"1.0.0.0/8",
		"1.1.1.0/24",
		"1.1.1.1/32",
		"0.0.0.0/0",
	} {
		t.Run(prefix, func(t *testing.T) {
			p := netip.MustParsePrefix(prefix)
			want := collectIter(t, r, p)
			got, _ := pageAll(t, r, p, 1)
			require.Equal(t, want, got)
		})
	}
}

// TestPagingCursorRejectsHostBits ensures a crafted token whose prefix
// address has host bits set is rejected rather than silently masked.
func TestPagingCursorRejectsHostBits(t *testing.T) {
	r, cursor := firstCursor(t, "MaxMind-DB-test-ipv4-24.mmdb",
		netip.MustParsePrefix("0.0.0.0/0"), 1)
	defer func() { require.NoError(t, r.Close()) }()

	payload := mustCursorPayload(t, cursor.String())
	// Byte 46 is within the 16-byte prefix address (payload offset 36..51);
	// set a host bit of the 0.0.0.0/0 prefix.
	payload[46] |= 0x01
	bad := encodeRawParts(payload, mustCursorMAC(t, cursor.String()))
	_, err := ParseNetworkCursor(bad)
	require.ErrorIs(t, err, ErrCursorCorrupt)
}

func mustCursorPayload(t *testing.T, token string) []byte {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 2)
	return mustBase64Raw(t, parts[0])
}

func mustCursorMAC(t *testing.T, token string) []byte {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 2)
	return mustBase64Raw(t, parts[1])
}
