package wplocale

import "testing"

func TestExtractWPLANGSingleQuoted(t *testing.T) {
	info := ExtractWPLANG(mustFixture(t, "wpconfig_wplang_de.php"))
	if !info.Found || info.Value != "de_DE" {
		t.Fatalf("WPLANG = found=%v value=%q, want found/de_DE", info.Found, info.Value)
	}
	if info.Conflicting {
		t.Fatalf("unexpected conflict: %v", info.Values)
	}
	if len(info.Values) != 1 {
		t.Fatalf("values = %v, want exactly [de_DE] (commented/other constants ignored)", info.Values)
	}
}

func TestExtractWPLANGDoubleQuoted(t *testing.T) {
	info := ExtractWPLANG(mustFixture(t, "wpconfig_wplang_double_quoted.php"))
	if !info.Found || info.Value != "fr_FR" {
		t.Fatalf("WPLANG = found=%v value=%q, want found/fr_FR", info.Found, info.Value)
	}
}

func TestExtractWPLANGConflicting(t *testing.T) {
	info := ExtractWPLANG(mustFixture(t, "wpconfig_wplang_conflicting.php"))
	if !info.Found || !info.Conflicting {
		t.Fatalf("WPLANG = found=%v conflicting=%v, want found+conflicting", info.Found, info.Conflicting)
	}
	if len(info.Values) != 2 {
		t.Fatalf("values = %v, want 2 entries", info.Values)
	}
}

func TestExtractWPLANGAbsent(t *testing.T) {
	src := []byte("<?php\ndefine('WP_HOME', 'https://example.com');\n$table_prefix = 'wp_';\n")
	info := ExtractWPLANG(src)
	if info.Found {
		t.Fatalf("WPLANG found=%v, want false", info.Found)
	}
}

func TestExtractWPLANGDefaultEmpty(t *testing.T) {
	src := []byte("<?php define('WPLANG', '');")
	info := ExtractWPLANG(src)
	if !info.Found || info.Value != "" {
		t.Fatalf("WPLANG = found=%v value=%q, want found/\"\" (classic default)", info.Found, info.Value)
	}
}

func TestExtractWPLANGDynamicValue(t *testing.T) {
	src := []byte("<?php $lang = 'de_DE'; define('WPLANG', $lang);")
	info := ExtractWPLANG(src)
	if !info.Found {
		t.Fatalf("WPLANG should be found")
	}
	if info.Static {
		t.Fatalf("dynamic WPLANG value must not be marked static")
	}
}

func TestExtractWPLANGIgnoresCommentedDefine(t *testing.T) {
	src := []byte("<?php\n// define('WPLANG', 'ru_RU');\n/* define(\"WPLANG\", \"es_ES\"); */\n")
	info := ExtractWPLANG(src)
	if info.Found {
		t.Fatalf("commented defines must be ignored, got %v", info.Values)
	}
}

func TestExtractWPLANGMethodCallNotDefine(t *testing.T) {
	src := []byte("<?php $obj->define('WPLANG', 'ru_RU'); Foo::define('WPLANG', 'es_ES');")
	info := ExtractWPLANG(src)
	if info.Found {
		t.Fatalf("method calls named define must be ignored, got %v", info.Values)
	}
}
