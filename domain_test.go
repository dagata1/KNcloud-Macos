package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseDomainResponse(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{`{"success":true,"message":"OK","data":{"domain":"https://www.kncloud.top","type":"cloud"}}`, "https://www.kncloud.top", true},
		{`{"success":true,"data":{"domain":"https://new.example.com/"}}`, "https://new.example.com", true},
		{`{"success":true,"data":{"domain":"http://insecure.com"}}`, "", false},
		{`{"success":false,"data":{"domain":"https://a.com"}}`, "", false},
		{`{"success":true,"data":{"domain":"https://a.com/path"}}`, "", false},
		{`{"success":true,"data":{"domain":"https://u:p@a.com"}}`, "", false},
		{`{"success":true,"data":{}}`, "", false},
		{`not json`, "", false},
	}
	for _, c := range cases {
		got, ok := parseDomainResponse([]byte(c.in))
		if got != c.want || ok != c.ok {
			t.Errorf("%s => %q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestFetchDynamicDomainFallback(t *testing.T) {
	old := kncloudDomainQueryURL
	defer func() { kncloudDomainQueryURL = old }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true,"data":{"domain":"https://new.kncloud.top"}}`))
	}))
	kncloudDomainQueryURL = srv.URL
	if d := fetchDynamicDomain("https://old.kncloud.top"); d != "https://new.kncloud.top" {
		t.Fatalf("got %s", d)
	}
	srv.Close()
	if d := fetchDynamicDomain("https://old.kncloud.top"); d != "https://old.kncloud.top" {
		t.Fatalf("fallback got %s", d)
	}
	if d := fetchDynamicDomain(""); d != kncloudDefaultDomain {
		t.Fatalf("default got %s", d)
	}
}
