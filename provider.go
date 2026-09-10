package httpacme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
)

// Provider is a deliberately small ACME DNS-01 adapter which turns a libdns
// record append into a configurable HTTP request.
//
// It is intended for services such as myaddr.tools which expose an HTTP API
// specifically for publishing the current ACME TXT value.
type Provider struct {
	Endpoint string            `json:"endpoint,omitempty"`
	Method   string            `json:"method,omitempty"`
	Body     string            `json:"body,omitempty"` // query, form, json
	Params   map[string]string `json:"params,omitempty"`
	Timeout  caddy.Duration    `json:"timeout,omitempty"`
	Result   *ResultConfig     `json:"result,omitempty"`

	client       *http.Client
	resultBodyRe *regexp.Regexp
}

// ResultConfig defines the response conditions that indicate a successful
// request. All configured conditions must match.
type ResultConfig struct {
	SuccessCode string `json:"success_code,omitempty"`
	SuccessBody string `json:"success_body,omitempty"`
	// SuccessBodyRegex treats SuccessBody as a regular expression instead of a
	// substring. The pattern is compiled during Provision.
	SuccessBodyRegex bool `json:"success_body_regex,omitempty"`
}

func init() {
	caddy.RegisterModule(Provider{})
}

func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.http_acme",
		New: func() caddy.Module { return new(Provider) },
	}
}

func (p *Provider) Provision(ctx caddy.Context) error {
	if p.Endpoint == "" {
		return fmt.Errorf("missing endpoint")
	}

	if p.Method == "" {
		p.Method = http.MethodPost
	}
	p.Method = strings.ToUpper(p.Method)
	switch p.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut:
	default:
		return fmt.Errorf("unsupported HTTP method %q (use GET, POST, or PUT)", p.Method)
	}

	if p.Body == "" {
		if p.Method == http.MethodGet {
			p.Body = "query"
		} else {
			p.Body = "form"
		}
	}
	p.Body = strings.ToLower(p.Body)
	switch p.Body {
	case "query", "form", "json":
	default:
		return fmt.Errorf("unsupported body mode %q (use query, form, or json)", p.Body)
	}

	if p.Params == nil || len(p.Params) == 0 {
		return fmt.Errorf("missing params")
	}
	if p.Result == nil {
		p.Result = &ResultConfig{}
	}
	var err error
	if p.Result.SuccessBodyRegex {
		if p.Result.SuccessBody == "" {
			return fmt.Errorf("success_body_regex requires success_body")
		}
		p.resultBodyRe, err = regexp.Compile(p.Result.SuccessBody)
		if err != nil {
			return fmt.Errorf("invalid success_body regex %q: %w", p.Result.SuccessBody, err)
		}
	}
	p.Result.SuccessCode, err = normalizeSuccessCode(p.Result.SuccessCode)
	if err != nil {
		return err
	}

	// Resolve normal Caddy placeholders now (e.g. {env.MYADDR_KEY}) while leaving
	// the runtime placeholders {http_acme.challenge}, {http_acme.zone}, and
	// {http_acme.fqdn} for Present(), where their values are known. ReplaceAll
	// must not be used here: it wipes unknown placeholders, which would turn
	// {http_acme.challenge} into an empty string before Present() can expand it.
	repl := caddy.NewReplacer()
	p.Endpoint = repl.ReplaceKnown(p.Endpoint, "")
	for k, v := range p.Params {
		p.Params[k] = repl.ReplaceKnown(v, "")
	}

	timeout := 30 * time.Second
	if p.Timeout > 0 {
		timeout = time.Duration(p.Timeout)
	}
	p.client = &http.Client{Timeout: timeout}
	return nil
}

// Present publishes the ACME TXT value through the configured HTTP endpoint.
// zone is the challenged zone and fqdn is the fully qualified record name, for
// example "_acme-challenge.example.com". Both are available to the
// configuration as {http_acme.zone} and {http_acme.fqdn}.
func (p *Provider) Present(ctx context.Context, zone, fqdn, challengeValue string) error {
	repl := caddy.NewReplacer()
	repl.Set("http_acme.challenge", challengeValue)
	repl.Set("http_acme.zone", zone)
	repl.Set("http_acme.fqdn", fqdn)

	params := make(map[string]string, len(p.Params))
	for k, v := range p.Params {
		params[k] = repl.ReplaceKnown(v, "")
	}

	req, err := p.buildRequest(ctx, repl.ReplaceKnown(p.Endpoint, ""), params)
	if err != nil {
		return err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("http_acme: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("http_acme: reading endpoint response: %w", err)
	}
	if !p.responseMatches(resp.StatusCode, body) {
		return fmt.Errorf("http_acme: endpoint result did not match: got %s and body %q; expected %s",
			resp.Status, strings.TrimSpace(string(body)), p.expectedResult())
	}

	return nil
}

// AppendRecords is the libdns entry point used by Caddy for an ACME TXT record.
// The PoC expects one or more TXT records and publishes each challenge in turn.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	for _, record := range records {
		rr := record.RR()
		if !strings.EqualFold(rr.Type, "TXT") {
			continue
		}
		// The zone may carry a trailing dot; strip it because HTTP APIs expect
		// bare names. AbsoluteName resolves the record name against the zone,
		// e.g. "_acme-challenge" in "example.com." becomes
		// "_acme-challenge.example.com.".
		fqdn := strings.TrimSuffix(libdns.AbsoluteName(rr.Name, zone), ".")
		if err := p.Present(ctx, strings.TrimSuffix(zone, "."), fqdn, rr.Data); err != nil {
			return nil, err
		}
	}
	return records, nil
}

// DeleteRecords is a no-op because myaddr.tools has no documented API for
// deleting one ACME challenge value. The service expires challenge values
// automatically.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return records, nil
}

// CleanUp is a no-op because myaddr.tools expires ACME TXT values
// automatically and does not document an explicit cleanup request.
func (p *Provider) CleanUp(ctx context.Context, domain, token string) error {
	return nil
}

func (p *Provider) buildRequest(ctx context.Context, params map[string]string) (*http.Request, error) {
	switch p.Body {
	case "query":
		u, err := url.Parse(p.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("http_acme: invalid endpoint: %w", err)
		}
		q := u.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
		return http.NewRequestWithContext(ctx, p.Method, u.String(), nil)

	case "form":
		values := url.Values{}
		for k, v := range params {
			values.Set(k, v)
		}
		req, err := http.NewRequestWithContext(ctx, p.Method, p.Endpoint, strings.NewReader(values.Encode()))
		if err != nil {
			return nil, fmt.Errorf("http_acme: creating request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json, text/plain, */*")
		return req, nil

	case "json":
		body, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("http_acme: encoding JSON: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, p.Method, p.Endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("http_acme: creating request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/plain, */*")
		return req, nil

	defaomain}", domain,
	)
	return r.Replace(value)
}

func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		// Support: dns http_acme <endpoint>
		if d.NextArg() {
			p.Endpoint = d.Val()
			if d.NextArg() {
				return d.ArgErr()
			}
		}

		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "endpoint":
				if !d.NextArg() || d.NextArg() {
					return d.ArgErr()
				}
				p.Endpoint = d.Val()
			case "method":
				if !d.NextArg() || d.NextArg() {
					return d.ArgErr()
				}
				p.Method = d.Val()
			case "body":
				if !d.NextArg() || d.NextArg() {
					return d.ArgErr()
				}
				p.Body = d.Val()
			case "timeout":
				if !d.NextArg() || d.NextArg() {
					return d.ArgErr()
				}
				timeout, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid timeout %q: %v", d.Val(), err)
				}
				p.Timeout = caddy.Duration(timeout)
			case "params":
				for nesting := d.Nesting(); d.NextBlock(nesting); {
					key := d.Val()
					if !d.NextArg() {
						return d.ArgErr()
					}
					if p.Params == nil {
						p.Params = make(map[string]string)
					}
					if _, exists := p.Params[key]; exists {
						return d.Errf("parameter %q already set", key)
					}
					p.Params[key] = d.Val()
					if d.NextArg() {
						return d.ArgErr()
					}
				}
			case "result":
				if p.Result == nil {
					p.Result = new(ResultConfig)
				}
				for nesting := d.Nesting(); d.NextBlock(nesting); {
					switch d.Val() {
					case "success_code":
						if !d.NextArg() || d.NextArg() {
							return d.ArgErr()
						}
						p.Result.SuccessCode = d.Val()
					case "success_body":
						if !d.NextArg() || d.NextArg() {
							return d.ArgErr()
						}
						p.Result.SuccessBody = d.Val()
					case "success_body_regex":
						if !d.NextArg() || d.NextArg() {
							return d.ArgErr()
						}
						v, err := strconv.ParseBool(d.Val())
						if err != nil {
							return d.Errf("invalid success_body_regex %q: use true or false", d.Val())
						}
						p.Result.SuccessBodyRegex = v
					default:
						return d.Errf("unrecognized result option %q", d.Val())
					}
				}
			default:
				return d.Errf("unrecognized subdirective %q", d.Val())
			}
		}
	}

	if p.Endpoint == "" {
		return d.Err("missing endpoint")
	}
	if len(p.Params) == 0 {
		return d.Err("missing params")
	}
	return nil
}

func normalizeSuccessCode(code string) (string, error) {
	code = strings.ToLower(strings.TrimSpace(code))
	if code == "" || code == "2xx" {
		return "2xx", nil
	}

	status, err := strconv.Atoi(code)
	if err != nil || status < 100 || status > 599 {
		return "", fmt.Errorf("invalid success_code %q (use an HTTP status code or 2xx)", code)
	}
	return strconv.Itoa(status), nil
}

func (p *Provider) responseMatches(status int, body []byte) bool {
	expectedCode := "2xx"
	expectedBody := ""
	if p.Result != nil {
		expectedCode = strings.ToLower(strings.TrimSpace(p.Result.SuccessCode))
		expectedBody = p.Result.SuccessBody
	}
	if !codeMatches {
		return false
	}
	if expectedBody == "" {
		return true
	}
	if p.resultBodyRe != nil {
		return p.resultBodyRe.Match(body)
	}
	return strings.Contains(string(body), expectedBody
		expectedCode = "2xx"
	}

	codeMatches := expectedCode == "2xx" && status >= http.StatusOK && status < http.StatusMultipleChoices
	if !codeMatches {
	if p.resultBodyRe != nil {
		return fmt.Sprintf("status %s and body matching /%s/", code, body)
	}
		expectedStatus, err := strconv.Atoi(expectedCode)
		codeMatches = err == nil && status == expectedStatus
	}
	return codeMatches && (expectedBody == "" || strings.Contains(string(body), expectedBody))
}

func (p *Provider) expectedResult() string {
	code := "2xx"
	body := ""
	if p.Result != nil {
		if p.Result.SuccessCode != "" {
			code = p.Result.SuccessCode
		}
		body = p.Result.SuccessBody
	}
	if body == "" {
		return fmt.Sprintf("status %s", code)
	}
	return fmt.Sprintf("status %s and body containing %q", code, body)
}

// Interface guards.
// ACME DNS challenges only require append + delete.
var (
	_ caddy.Module          = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
