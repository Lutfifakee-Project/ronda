package wplocale

import "testing"

func segKinds(segs []Segment) []SegKind {
	out := make([]SegKind, len(segs))
	for i, s := range segs {
		out[i] = s.Kind
	}
	return out
}

func TestSegmentsStringCommentSplit(t *testing.T) {
	src := []byte(`<?php
$a = 'hello // not a comment';   // real comment
$b = "url http://x/*y*/ z";      # hash comment
/* block /* nested-ish */
$c = 1;`)
	segs := Segments(src)
	masked := MaskSource(src, segs)

	// Code view must not contain the string contents or comments.
	code := string(nonZero(masked))
	for _, banned := range []string{"hello", "http://x", "real comment", "hash comment", "nested"} {
		if contains(code, banned) {
			t.Fatalf("masked code view leaks %q:\n%s", banned, code)
		}
	}
	if !contains(code, "$a =") || !contains(code, "$c = 1;") {
		t.Fatalf("code view lost code:\n%s", code)
	}
}

func TestSegmentsBacktickIsString(t *testing.T) {
	src := []byte("$a = `id`; $b = 2;")
	segs := Segments(src)
	masked := MaskSource(src, segs)
	code := string(nonZero(masked))
	if contains(code, "id") {
		t.Fatalf("backtick body not masked: %q", code)
	}
	if !contains(code, "$b = 2;") {
		t.Fatalf("code after backtick lost: %q", code)
	}
	var sawBacktick bool
	for _, s := range segs {
		if s.Kind == SegString && s.Quote == '`' && s.Value == "id" {
			sawBacktick = true
		}
	}
	if !sawBacktick {
		t.Fatalf("backtick literal not captured as string segment: %+v", segs)
	}
}

func TestHeredocNowdocMasking(t *testing.T) {
	src := []byte("<?php\n$x = <<<EOT\nsome $wp_local_package = 'ja'; text\nEOT;\n$y = <<<'EOT'\n$wp_local_package = 'de_DE';\nEOT;\n$z = 1;")
	segs := Segments(src)
	masked := MaskSource(src, segs)
	code := string(nonZero(masked))
	if contains(code, "documentation") || contains(code, "some") || contains(code, "static") {
		t.Fatalf("heredoc/nowdoc bodies leaked into code view: %q", code)
	}
	if !contains(code, "$z = 1;") {
		t.Fatalf("code after heredoc lost: %q", code)
	}
	// Nowdoc must be flagged as nowdoc.
	var sawNowdoc bool
	for _, s := range segs {
		if s.Kind == SegString && s.Nowdoc {
			sawNowdoc = true
		}
	}
	if !sawNowdoc {
		t.Fatalf("nowdoc not detected in segments: %+v", segs)
	}
}

func TestDoubleQuoteInterpolationFlag(t *testing.T) {
	segs := Segments([]byte(`$a = "plain"; $b = "has $var"; $c = "dollar \$ escaped";`))
	var plain, interp bool
	for _, s := range segs {
		if s.Kind != SegString {
			continue
		}
		switch s.Value {
		case "plain":
			if s.Interpolated {
				t.Fatalf(`"plain" wrongly flagged interpolated`)
			}
			plain = true
		case "has $var":
			if !s.Interpolated {
				t.Fatalf(`"has $var" not flagged interpolated`)
			}
			interp = true
		case "dollar \\$ escaped":
			if s.Interpolated {
				t.Fatalf(`escaped \$ wrongly flagged interpolated`)
			}
			plain = true
		}
	}
	if !plain || !interp {
		t.Fatalf("expected both string kinds, got plain=%v interp=%v", plain, interp)
	}
}

func TestAttributeHashIsNotComment(t *testing.T) {
	src := []byte("<?php\n#[Attr]\n$x = 1;")
	segs := Segments(src)
	for _, s := range segs {
		if s.Kind == SegComment && s.Start <= 7 && s.End >= 2 {
			t.Fatalf("#[Attr] misclassified as comment: %+v", segs)
		}
	}
}

func nonZero(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c != 0 {
			out = append(out, c)
		}
	}
	return out
}

func contains(hay, needle string) bool {
	return len(needle) > 0 && len(hay) >= len(needle) && stringContains(hay, needle)
}

func stringContains(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
