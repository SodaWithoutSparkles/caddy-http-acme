package httpacme

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
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
			"acme_challenge": "{challenge}",
			"domain":         "{domain}",
		},
	}
	p.client = srv.Client()

	if err := p.Present(context.Background(), "example.com", "txt-value"); err != nil {
		t.Fatal(err)
	}

	body := <-got
	if body["key"] != "secret" || body["acme_challenge"] != "txt-value" || body["domain"] != "example.com" {
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
		"acme_challenge": "{challenge}",
	}, client: srv.Client()}

	if err := p.Present(context.Background(), "example.com", "txt+value"); err != nil {
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

	if err := p.Present(context.Background(), "example.com", "x"); err == nil {
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

			if err := p.Present(context.Background(), "example.com", "challenge"); (err != nil) != tt.wantErr {
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

	if err := p.Present(context.Background(), "example.com", "challenge"); err != nil {
		t.Fatal(err)
	}
}

func TestCaddyfile(t *testing.T) {
	input := `http_acme {
        endpoint https://myaddr.tools/update
        method POST
        body json
        params {
            key {env.MYADDR_KEY}
            acme_challenge {challenge}
        }
		result {
			success_code 200
			success_body "OK"
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
	if p.Params["acme_challenge"] != "{challenge}" {
		t.Fatalf("unexpected challenge param: %#v", p.Params)
	}
	if p.Result == nil || p.Result.SuccessCode != "200" || p.Result.SuccessBody != "OK" {
		t.Fatalf("unexpected result config: %#v", p.Result)
	}
}
