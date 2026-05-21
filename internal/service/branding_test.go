package service

import "testing"

func TestIsValidHostname(t *testing.T) {
	good := []string{
		"login.customer.com",
		"x.io",
		"sub.sub.example.co.uk",
		"x1.x2.x3",
	}
	for _, h := range good {
		if !isValidHostname(h) {
			t.Errorf("expected %q to be valid", h)
		}
	}
	bad := []string{
		"",
		"-bad.example.com",   // leading hyphen
		"bad-.example.com",   // trailing hyphen on label
		"example",            // no TLD
		"a..b",               // empty label
		"UPPERCASE.com",      // capitals (we lowercase first; we want the regex to be strict on the *post-lowercase* value)
	}
	for _, h := range bad {
		if isValidHostname(h) {
			t.Errorf("expected %q to be invalid", h)
		}
	}
}

func TestNormaliseHost(t *testing.T) {
	cases := map[string]string{
		"  Example.COM  ":     "example.com",
		"example.com:8080":    "example.com",
		"login.cust.com:443":  "login.cust.com",
		"":                    "",
	}
	for in, want := range cases {
		if got := normaliseHost(in); got != want {
			t.Errorf("normaliseHost(%q) = %q want %q", in, got, want)
		}
	}
}

func TestIsHexColor(t *testing.T) {
	good := []string{"#0ea5e9", "#FFFFFF", "#000000", "#abcdef"}
	for _, c := range good {
		if !isHexColor(c) {
			t.Errorf("expected %q valid", c)
		}
	}
	bad := []string{"", "0ea5e9", "#abc", "#zzzzzz", "rgb(0,0,0)"}
	for _, c := range bad {
		if isHexColor(c) {
			t.Errorf("expected %q invalid", c)
		}
	}
}
