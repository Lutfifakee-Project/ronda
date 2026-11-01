package kernelintel

import (
	"bufio"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// The release-scoped Debian loader must retain exactly the subset the
// unscoped loader would produce for that release: MatchDebian filters by
// release anyway, so scoping may never change a verdict. It also must not
// crash on entries without the kept release, DSA keys, or malformed shapes.
func TestDebianScopedParseMatchesUnscopedSubset(t *testing.T) {
	fixture := `{
 "linux": {
  "CVE-2024-1086": {
   "description": "use-after-free in netfilter",
   "releases": {
    "bookworm": {"status": "resolved", "fixed_version": "6.1.94-1", "urgency": "high"},
    "buster": {"status": "vulnerable", "fixed_version": null, "urgency": "high"},
    "sid": {"status": "resolved", "fixed_version": "6.8.1-1", "urgency": "high"}
   }
  },
  "CVE-2024-26759": {
   "releases": {
    "bookworm": {"status": "resolved", "fixed_version": "6.1.82-1", "urgency": "medium"}
   }
  },
  "CVE-2023-52617": {
   "releases": {
    "sid": {"status": "resolved", "fixed_version": "6.7.7-1", "urgency": "medium"}
   }
  },
  "DSA-5678-1": {
   "releases": {
    "bookworm": {"status": "resolved", "fixed_version": "6.1.90-1", "urgency": "high"}
   }
  }
 },
 "not-the-kernel": {
  "CVE-2024-0001": {
   "releases": {
    "bookworm": {"status": "vulnerable", "fixed_version": null, "urgency": "high"}
   }
  }
 }
}`

	all, _, err := loadDebianTracker(bufio.NewReader(strings.NewReader(fixture)))
	if err != nil {
		t.Fatalf("unscoped parse: %v", err)
	}
	scoped, _, err := debianTrackerLoader("bookworm")(bufio.NewReader(strings.NewReader(fixture)))
	if err != nil {
		t.Fatalf("scoped parse: %v", err)
	}

	// Expected: the unscoped advisories restricted to bookworm.
	var want []Advisory
	for _, a := range all {
		if a.Release == "bookworm" {
			want = append(want, a)
		}
	}
	if len(want) == 0 {
		t.Fatal("fixture produced no bookworm advisories for the unscoped loader")
	}
	if !reflect.DeepEqual(want, scoped) {
		t.Fatalf("scoped subset differs:\nwant %+v\ngot  %+v", want, scoped)
	}

	// Non-kernel sources and other releases never leak in.
	for _, a := range scoped {
		if a.Release != "bookworm" {
			t.Errorf("scoped advisory for release %q leaked", a.Release)
		}
		if a.Package != "linux" {
			t.Errorf("non-kernel package %q leaked", a.Package)
		}
	}
	if len(scoped) != 2 {
		t.Fatalf("expected 2 bookworm advisories (DSA key excluded), got %d", len(scoped))
	}
}

// Truncation under the advisory bound stays deterministic in the scoped path
// and keeps the same (CVE, package) order the unscoped path guarantees.
func TestDebianScopedParseTruncationDeterministic(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"linux":{`)
	for i := 0; i < 50; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"` + cveName(1000+i) + `":{"releases":{"bookworm":{"status":"vulnerable","fixed_version":null,"urgency":"high"},"sid":{"status":"resolved","fixed_version":"9.9.9-1","urgency":"high"}}}`)
	}
	b.WriteString(`}}`)

	old := maxAdvisoriesPerFeed
	maxAdvisoriesPerFeed = 10
	defer func() { maxAdvisoriesPerFeed = old }()

	first, _, err := debianTrackerLoader("bookworm")(bufio.NewReader(strings.NewReader(b.String())))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	second, _, err := debianTrackerLoader("bookworm")(bufio.NewReader(strings.NewReader(b.String())))
	if err != nil {
		t.Fatalf("parse 2: %v", err)
	}
	if len(first) != 10 {
		t.Fatalf("bound not applied: %d", len(first))
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("truncated subsets differ between identical parses")
	}
	for i := 1; i < len(first); i++ {
		if first[i-1].CVE >= first[i].CVE {
			t.Fatalf("truncated output not sorted by CVE at %d: %s >= %s", i, first[i-1].CVE, first[i].CVE)
		}
	}
}

func cveName(n int) string {
	// CVE-YYYY-NNNN with zero padding, deterministic for the fixture.
	return "CVE-2024-" + string([]byte{
		byte('0' + (n/1000)%10), byte('0' + (n/100)%10), byte('0' + (n/10)%10), byte('0' + n%10),
	})
}

// The releases filter must tolerate non-object releases and unknown shapes
// by failing loudly instead of silently producing an empty dataset.
func TestDebianScopedParseRejectsMalformedReleases(t *testing.T) {
	fixture := `{"linux":{"CVE-2024-1":{"releases":"not-an-object"}}}`
	_, _, err := debianTrackerLoader("bookworm")(bufio.NewReader(strings.NewReader(fixture)))
	if err == nil {
		t.Fatal("malformed releases must fail the parse")
	}
	// Raw JSON decode sanity for the filter type itself.
	var rel debianReleasesFor
	rel.Keep = "bookworm"
	if err := json.Unmarshal([]byte(`{"buster":{"status":"vulnerable"},"bookworm":{"status":"resolved","fixed_version":"1.2-3"}}`), &rel); err != nil {
		t.Fatalf("filter unmarshal: %v", err)
	}
	if !rel.Present || rel.Status.FixedVersion != "1.2-3" {
		t.Fatalf("kept release not captured: %+v", rel)
	}
}
