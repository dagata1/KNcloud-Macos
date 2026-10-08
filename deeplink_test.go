package main

import "testing"

func TestParseDeepLink(t *testing.T) {
	ok := []struct{ raw, cur, domain, email string }{
		{"kncloud://login?token=abc&email=a%40b.c&domain=https%3A%2F%2Fwww.kncloud.top&sub_url=x", "", "https://www.kncloud.top", "a@b.c"},
		{"kncloud://login?token=abc&domain=https://KNcloud.top/", "", "https://kncloud.top", ""},
		{"kncloud://login?token=abc&domain=https://panel.example.net", "https://panel.example.net", "https://panel.example.net", ""},
		{"kncloud://login?auth_data=abc", "", "https://www.kncloud.top", ""},
		{"KNCLOUD://LOGIN?token=abc", "", "https://www.kncloud.top", ""},
	}
	for _, c := range ok {
		l, err := parseDeepLink(c.raw, c.cur)
		if err != nil {
			t.Fatalf("%s: %v", c.raw, err)
		}
		if l.Domain != c.domain || l.Email != c.email || l.Token != "abc" {
			t.Fatalf("%s: got %+v", c.raw, l)
		}
	}
	bad := []struct{ raw, cur string }{
		{"kncloud://login?domain=https://www.kncloud.top", ""},
		{"kncloud://login?token=a&domain=http://www.kncloud.top", ""},
		{"kncloud://login?token=a&domain=https://evilkncloud.top", ""},
		{"kncloud://login?token=a&domain=https://kncloud.top.evil.com", ""},
		{"kncloud://login?token=a&domain=https://kncloud.top@evil.com", ""},
		{"kncloud://login?token=a&domain=https://user@www.kncloud.top", ""},
		{"kncloud://login?token=a&domain=https://www.kncloud.top/path", ""},
		{"kncloud://login?token=a&domain=https://panel.example.net", ""},
		{"kncloud://login?token=a&domain=https://sub.panel.example.net", "https://panel.example.net"},
		{"kncloud://logout?token=a", ""},
		{"https://www.kncloud.top", ""},
	}
	for _, c := range bad {
		if l, err := parseDeepLink(c.raw, c.cur); err == nil {
			t.Fatalf("%s: expected error, got %+v", c.raw, l)
		}
	}
}

func TestFindDeepLinkArg(t *testing.T) {
	if got := findDeepLinkArg([]string{`"kncloud://login?token=a"`}); got != "kncloud://login?token=a" {
		t.Fatal(got)
	}
	if got := findDeepLinkArg([]string{"--tun-selftest"}); got != "" {
		t.Fatal(got)
	}
}
