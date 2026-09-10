package httpacme

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
)

func TestJSONRequestAndRuntimeExpansion(t *testing.T) {
	got := make(chan map[string]string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
			return
		}
		got <- body
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	p := &Provider{
		Endpoint: srv.URL,
		Method:   "POST",
		Body:     "json",
		Params: map[string]string{
			"key":            "secret",
			"acme_challenge": "{http_acme.challenge}",
			"zone":           "{http_acme.zone}",
			"fqdn":           "{http_acme.fqdn}",
		},
	}
	p.client = srv.Client()

	if err := p.Present(context.Background(), "example.com", "_acme-challenge.example.com", "txt-value"); err != nil {
		t.Fatal(err)
	}

	body := <-got
	if body["key"] != "secret" || body["acme_challenge"] != "txt-value" ||
		body["zone"] != "example.com" || body["fqdn"] != "_acme-challenge.example.com" {
		t.Fatalf("unexpected body: %#v", body)
	}
}

func TestQueryRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "secret" || r.URL.Query().Get("acme_challenge") != "txt+value" {
			t.Fatalf("unexpected query: %s", r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := &Provider{Endpoint: srv.URL, Method: "GET", Body: "query", Params: map[string]string{
		"key":            "secret",
		"acme_challenge": "{http_acme.challenge}",
	}, client: srv.Client()}

	if err := p.Present(context.Background(), "example.com", "_acme-challenge.example.com", "txt+value"); err != nil {
		t.Fatal(err)
	}
}

func TestNon2xxIncludesResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad key", http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := &Provider{Endpoint: srv.URL, Method: "POST", Body: "form", Params: map[string]string{
		"key": "bad",
	}, client: srv.Client()}

	if err := p.Present(context.Background(), "example.com", "_acme-challenge.example.com", "x"); err == nil {
		t.Fatal("expected error")
	}
}

func TestResultRequiresAllConfiguredConditions(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		wantErr    bool
	}{
		{name: "matching status and body", status: http.StatusOK, body: "accepted", wantErr: false},
		{name: "wrong status", status: http.StatusCreated, body: "accepted", wantErr: true},
		{name: "wrong body", status: http.StatusOK, body: "rejected", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			p := &Provider{
				Endpoint: srv.URL,
				Method:   http.MethodPost,
				Body:     "form",
				Params:   map[string]string{"key": "secret"},
				Result:   &ResultConfig{SuccessCode: "200", SuccessBody: "accepted"},
				client:   srv.Client(),
			}

			if err := p.Present(context.Background(), "example.com", "_acme-challenge.example.com", "challenge"); (err != nil) != tt.wantErr {
				t.Fatalf("Present() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestResult2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	p := &Provider{
		Endpoint: srv.URL,
		Method:   http.MethodPost,
		Body:     "form",
		Params:   map[string]string{"key": "secret"},
		Result:   &ResultConfig{SuccessCode: "2xx"},
		client:   srv.Client(),
	}

	if err := p.Present(context.Background(), "example.com", "_acme-challenge.example.com", "challenge"); err != nil {
		t.Fatal(err)
	}
}

func TestCaddyfile(t *testing.T) {
	input := `http_acme {
        endpoint https://myaddr.tools/update
        method POST
        body json
        params {
            key abcdef
            acme_challenge {http_acme.challenge}
        }
		result {
			success_code 200
			success_body "OK"
			success_body_regex true
		}
    }`

	d := caddyfile.NewTestDispenser(input)
	p := new(Provider)
	if err := p.UnmarshalCaddyfile(d); err != nil {
		t.Fatal(err)
	}

	if p.Endpoint != "https://myaddr.tools/update" || p.Method != "POST" || p.Body != "json" {
		t.Fatalf("unexpected config: %#v", p)
	}
	if p.Params["acme_challenge"] != "{http_acme.challenge}" {
		t.Fatalf("unexpected challenge param: %#v", p.Params)
	}
	if p.Result == nil || p.Result.SuccessCode != "200" || p.Result.SuccessBody != "OK" || !p.Result.SuccessBodyRegex {
		t.Fatalf("unexpected result config: %#v", p.Result)
	}
}

// Regression test: Provision() must resolve Caddy's own placeholders but leave
// the runtime placeholders for Present() to expand. ReplaceAll() previously
// turned {http_acme.challenge} into an empty string during Provision, so
// myaddr.tools received {"acme_challenge": ""} and answered:
// 400 must specify either "ip" or "acme_challenge".
func TestProvisionKeepsRuntimePlaceholdersForPresent(t *testing.T) {
	t.Setenv("HTTP_ACME_TEST_KEY", "secret")

	got := make(chan map[string]string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		got <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := &Provider{
		Endpoint: srv.URL,
		Method:   "POST",
		Body:     "json",
		Params: map[string]string{
			"key":            "{env.HTTP_ACME_TEST_KEY}",
			"acme_challenge": "{http_acme.challenge}",
		},
	}
	if err := p.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatal(err)
	}
	if p.Params["key"] != "secret" {
		t.Fatalf("env placeholder not resolved: %#v", p.Params)
	}
	if p.Params["acme_challenge"] != "{http_acme.challenge}" {
		t.Fatalf("Provision consumed the runtime placeholder: %#v", p.Params)
	}

	p.client = srv.Client()
	if err := p.Present(context.Background(), "donuts.myaddr.tools", "_acme-challenge.donuts.myaddr.tools", "txt-value"); err != nil {
		t.Fatal(err)
	}
	body := <-got
	if body["key"] != "secret" || body["acme_challenge"] != "txt-value" {
		t.Fatalf("unexpected body: %#v", body)
	}
}

func TestAppendRecordsExpandsZoneAndFQDN(t *testing.T) {
	got := make(chan map[string]string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		got <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := &Provider{
		Endpoint: srv.URL,
		Method:   "POST",
		Body:     "json",
		Params: map[string]string{
			"challenge": "{http_acme.challenge}",
			"zone":      "{http_acme.zone}",
			"fqdn":      "{http_acme.fqdn}",
		},
		client: srv.Client(),
	}

	// Caddy may pass the zone with a trailing dot; the FQDN must be derived
	// from the record name relative to that zone.
	records := []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "txt-value"},
	}
	if _, err := p.AppendRecords(context.Background(), "example.com.", records); err != nil {
		t.Fatal(err)
	}

	body := <-got
	if body["challenge"] != "txt-value" || body["zone"] != "example.com" || body["fqdn"] != "_acme-challenge.example.com" {
		t.Fatalf("unexpected body: %#v", body)
	}
}

func TestUnknownAndLegacyPlaceholdersStayLiteral(t *testing.T) {
	got := make(chan map[string]string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		got <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := &Provider{
		Endpoint: srv.URL,
		Method:   "POST",
		Body:     "json",
		Params: map[string]string{
			"legacy":  "{challenge}",
			"unknown": "{http_acme.typo}",
		},
		client: srv.Client(),
	}

	if err := p.Present(context.Background(), "example.com", "_acme-challenge.example.com", "txt-value"); err != nil {
		t.Fatal(err)
	}

	body := <-got
	if body["legacy"] != "{challenge}" || body["unknown"] != "{http_acme.typo}" {
		t.Fatalf("unknown placeholders must stay literal, got: %#v", body)
	}
}

func TestResultBodyRegex(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "regex matches", body: "accepted id=123", wantErr: false},
		{name: "regex does not match", body: "rejected", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			p := &Provider{
				Endpoint: srv.URL,
				Method:   http.MethodPost,
				Body:     "form",
				Params:   map[string]string{"key": "secret"},
				Result:   &ResultConfig{SuccessBody: `accepted id=\d+`, SuccessBodyRegex: true},
			}
			if err := p.Provision(caddy.Context{Context: context.Background()}); err != nil {
				t.Fatal(err)
			}

			if err := p.Present(context.Background(), "example.com", "_acme-challenge.example.com", "challenge"); (err != nil) != tt.wantErr {
				t.Fatalf("Present() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestResultBodyRegexProvision(t *testing.T) {
	tests := []struct {
		name    string
		result  ResultConfig
		wantErr bool
	}{
		{name: "valid regex", result: ResultConfig{SuccessBody: `^ok$`, SuccessBodyRegex: true}},
		{name: "invalid regex", result: ResultConfig{SuccessBody: `(`, SuccessBodyRegex: true}, wantErr: true},
		{name: "regex without body", result: ResultConfig{SuccessBodyRegex: true}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{
				Endpoint: "https://example.com",
				Params:   map[string]string{"key": "secret"},
				Result:   &tt.result,
			}
			err := p.Provision(caddy.Context{Context: context.Background()})
			if (err != nil) != tt.wantErr {
				t.Fatalf("Provision() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
