package versioncmp

import "testing"

func TestCompareDebian(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.0.1", -1},
		{"1.0.1", "1.0", 1},
		{"1.0", "1.00", 0},     // numeric runs ignore leading zeros
		{"1.01", "1.1", 0},     // dpkg numeric compare ignores leading zeros
		{"2:1.0", "1:9.9", 1},  // epoch dominates
		{"0:1.0", "1.0", 0},    // missing epoch equals epoch 0
		{"1.0~rc1", "1.0", -1}, // tilde sorts before end
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~~", "1.0~a", -1}, // tilde before letters
		{"1.0-1", "1.0-2", -1}, // revision compares
		{"1.0-1", "1.0-1", 0},
		{"1.0", "1.0-1", -1}, // native version equals revision 0
		{"1.0-1", "1.0-1ubuntu1", -1},
		{"1.0-1~bpo1", "1.0-1", -1}, // backport revision sorts lower
		{"6.1.90-1", "6.1.91-1", -1},
		{"6.1.37-1", "6.1.100-1", -1}, // 37 < 100 numerically
		{"1.0a", "1.0.1", -1},         // dpkg: letters sort below punctuation
		{"1.0a", "1.0b", -1},
		{"1.0-18-amd64", "1.0-19-amd64", -1},
		{"6.1.0-18", "6.1.0-9", 1},
	}
	for _, c := range cases {
		got, err := CompareDebian(c.a, c.b)
		if err != nil {
			t.Fatalf("CompareDebian(%q, %q): unexpected error %v", c.a, c.b, err)
		}
		if got != c.want {
			t.Errorf("CompareDebian(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareDebianInvalid(t *testing.T) {
	cases := [][2]string{
		{"", "1.0"},
		{"1.0", ""},
		{"x:1.0", "1.0"},  // non-numeric epoch
		{"-1:1.0", "1.0"}, // negative epoch
		{":1.0", "1.0"},   // empty epoch
		{"1:", "1.0"},     // missing upstream after epoch
		{"-1.0", "1.0"},   // empty upstream before revision
	}
	for _, c := range cases {
		if _, err := CompareDebian(c[0], c[1]); err == nil {
			t.Errorf("CompareDebian(%q, %q) = nil error, want invalid-syntax error", c[0], c[1])
		}
	}
}

func TestCompareRPM(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"4.18.0-553.el8", "4.18.0-553.el8", 0},
		{"4.18.0-553.5.1.el8_10", "4.18.0-553.el8", 1},
		{"5.14.0-427.13.1.el9_4", "5.14.0-427.13.1.el9_5", -1},
		{"1:1.0-1", "2.0-1", 1}, // epoch dominates
		{"0:1.0-1", "1.0-1", 0}, // missing epoch equals 0
		{"1.05-1", "1.5-1", 0},  // leading zeros ignored
		{"1.0~rc1-1", "1.0-1", -1},
		{"1.0^git1-1", "1.0-1", 1}, // caret continuation above base
		{"1.0^git1", "1.0a", -1},   // caret below a real letter continuation
		{"1.0-1", "1.0-2", -1},
		{"6.6.4-200.fc40", "6.6.4-201.fc40", -1},
		{"6.6.9-200.fc40", "6.6.10-200.fc40", -1}, // 9 < 10 numerically
		{"1.0", "1.0-1", -1},                      // missing release sorts below
		{"2.6.32-754.35.1.el6", "2.6.32-754.el6", 1},
	}
	for _, c := range cases {
		got, err := CompareRPM(c.a, c.b)
		if err != nil {
			t.Fatalf("CompareRPM(%q, %q): unexpected error %v", c.a, c.b, err)
		}
		if got != c.want {
			t.Errorf("CompareRPM(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareRPMInvalid(t *testing.T) {
	cases := [][2]string{
		{"", "1.0"},
		{"x:1.0-1", "1.0-1"},
		{"1.0", ""},
	}
	for _, c := range cases {
		if _, err := CompareRPM(c[0], c[1]); err == nil {
			t.Errorf("CompareRPM(%q, %q) = nil error, want invalid-syntax error", c[0], c[1])
		}
	}
}

func TestCompareArch(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"6.6.2.arch1-1", "6.6.2.arch1-1", 0},
		{"6.6.2.arch1-1", "6.6.2.arch1-2", -1},
		{"6.6.2.arch1-1", "6.6.3.arch1-1", -1},
		{"6.1.1.zen1-1", "6.1.2.zen1-1", -1},
		{"6.6.9.hardened1-1", "6.6.10.hardened1-1", -1},
		{"6.0~rc1-1", "6.0-1", -1}, // pacman tilde support
		// vercmp(8): pkgrel only compares when present on both sides
		{"2.0", "2.0-13", 0},
		{"1.5-1", "1.5", 0},
		{"1.5-1", "1.5-2", -1},
		// vercmp(8): 1.0a < 1.0b < 1.0beta < 1.0p < 1.0pre < 1.0rc < 1.0
		//            < 1.0.a < 1.0.1
		{"1.0a", "1.0", -1},
		{"1.0b", "1.0", -1},
		{"1.0beta", "1.0p", -1},
		{"1.0p", "1.0pre", -1},
		{"1.0pre", "1.0rc", -1},
		{"1.0rc", "1.0", -1},
		{"1.0", "1.0.a", -1},
		{"1.0.a", "1.0.1", -1},
		{"1.0a", "1.0.1", -1},
		// vercmptest.sh: same content, differing separators
		{"2.0", "2_0", 0},
		{"2.0_a", "2_0.a", 0},
		{"2.0a", "2.0.a", -1},
		{"2___a", "2_a", 1},
		{"1:1.0-1", "2:0.9-9", -1}, // epoch overrules
		{"1.0-1", "1.0a-1", 1},     // 1.0a < 1.0, so 1.0-1 > 1.0a-1
	}
	for _, c := range cases {
		got, err := CompareArch(c.a, c.b)
		if err != nil {
			t.Fatalf("CompareArch(%q, %q): unexpected error %v", c.a, c.b, err)
		}
		if got != c.want {
			t.Errorf("CompareArch(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareArchInvalid(t *testing.T) {
	cases := [][2]string{
		{"", "1.0-1"},
		{"1.0-1", ""},
	}
	for _, c := range cases {
		if _, err := CompareArch(c[0], c[1]); err == nil {
			t.Errorf("CompareArch(%q, %q) = nil error, want invalid-syntax error", c[0], c[1])
		}
	}
}

func TestCompareAlpine(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"6.6.58-r0", "6.6.58-r0", 0},
		{"6.6.58-r0", "6.6.59-r0", -1},
		{"6.6.58-r0", "6.6.58-r1", -1},
		{"6.6.58-r10", "6.6.58-r9", 1},
		{"6.6.58", "6.6.58-r0", -1},   // revision continues the version
		{"6.6.9-r0", "6.6.10-r0", -1}, // numeric, not lexicographic
		// apk-tools suffix table: alpha < beta < pre < rc < none
		{"1.0_alpha", "1.0", -1},
		{"1.0_alpha1", "1.0_alpha2", -1},
		{"1.0_beta", "1.0_rc1", -1},
		{"1.0_rc1", "1.0", -1},
		{"1.0", "1.0_p1", -1},  // p is post-release
		{"1.0", "1.0_cvs", -1}, // cvs/svn/git/hg are post-release in apk
		{"1.0_alpha", "1.0_beta", -1},
		{"1.0", "1.0a", -1}, // trailing letter continues the version
		{"1.0a", "1.0b", -1},
		// Pre-release suffixes sort below the plain release even with the
		// same upstream digits.
		{"3.0", "3.0_alpha20240101-r1", 1},
		{"6.06.58-r0", "6.6.58-r0", -1}, // leading zeros compare as strings
		{"6.6.58_rc1-r0", "6.6.58-r0", -1},
	}
	for _, c := range cases {
		got, err := CompareAlpine(c.a, c.b)
		if err != nil {
			t.Fatalf("CompareAlpine(%q, %q): unexpected error %v", c.a, c.b, err)
		}
		if got != c.want {
			t.Errorf("CompareAlpine(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareAlpineInvalid(t *testing.T) {
	cases := [][2]string{
		{"", "1.0-r0"},
		{"1.0-r0", ""},
		{"1.0~git1-r0", "1.0-r0"},  // '~' snapshot marker unsupported
		{"1.0-r0-r1", "1.0-r0"},    // double revision
		{"1.0-x1", "1.0-r0"},       // malformed revision
		{"1.0-r", "1.0-r0"},        // revision without number
		{"1.0_unknown1", "1.0-r0"}, // unknown suffix
		{"1.0.1", "1.0_p1"},        // unsupported token mix
	}
	for _, c := range cases {
		if _, err := CompareAlpine(c[0], c[1]); err == nil {
			t.Errorf("CompareAlpine(%q, %q) = nil error, want invalid-syntax error", c[0], c[1])
		}
	}
}
