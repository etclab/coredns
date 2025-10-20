package etcd_calypso

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/etcd_calypso/msg"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

const (
	WKDIBEOptionCode  = 65002 // EDNS option code for WKDIBE encrypted records
	CalypsoOptionCode = 65003 // EDNS option code for Calypso encrypted records with searchtag
)

// RequestType represents the type of encryption request
type RequestType int

const (
	RequestTypeRegular RequestType = iota
	RequestTypeWKDIBE
	RequestTypeCalypso
)

// parseEDNSOptions parses EDNS options and returns request type and searchtag (if Calypso)
func parseEDNSOptions(r *dns.Msg) (RequestType, string) {
	opt := r.IsEdns0()
	if opt == nil {
		return RequestTypeRegular, ""
	}

	for _, option := range opt.Option {
		switch option.Option() {
		case WKDIBEOptionCode:
			return RequestTypeWKDIBE, ""
		case CalypsoOptionCode:
			// Extract searchtag from payload
			if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
				return RequestTypeCalypso, string(localOpt.Data)
			}
		}
	}

	return RequestTypeRegular, ""
}

// ServeDNS implements the plugin.Handler interface.
func (e *Etcd) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	opt := plugin.Options{}
	state := request.Request{W: w, Req: r}

	zone := plugin.Zones(e.Zones).Matches(state.Name())
	if zone == "" {
		return plugin.NextOrFailure(e.Name(), e.Next, ctx, w, r)
	}

	// Parse EDNS options to determine request type
	reqType, searchtag := parseEDNSOptions(r)

	// Route based on request type
	switch reqType {
	case RequestTypeCalypso:
		return e.handleCalypsoRequest(ctx, w, r, state, zone, searchtag, opt)
	case RequestTypeWKDIBE:
		return e.handleWKDIBERequest(ctx, w, r, state, zone, opt)
	case RequestTypeRegular:
		return e.handleRegularRequest(ctx, w, r, state, zone, opt)
	}

	return dns.RcodeServerFailure, nil
}

// handleRegularRequest handles standard DNS queries (skip encrypted records)
func (e *Etcd) handleRegularRequest(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, state request.Request, zone string, opt plugin.Options) (int, error) {
	var (
		records, extra []dns.RR
		truncated      bool
		err            error
	)

	switch state.QType() {
	case dns.TypeA:
		records, truncated, err = plugin.A(ctx, e, zone, state, nil, opt)
	case dns.TypeAAAA:
		records, truncated, err = plugin.AAAA(ctx, e, zone, state, nil, opt)
	case dns.TypeTXT:
		records, truncated, err = plugin.TXT(ctx, e, zone, state, nil, opt)
	case dns.TypeCNAME:
		records, err = plugin.CNAME(ctx, e, zone, state, opt)
	case dns.TypePTR:
		records, err = plugin.PTR(ctx, e, zone, state, opt)
	case dns.TypeMX:
		records, extra, err = plugin.MX(ctx, e, zone, state, opt)
	case dns.TypeSRV:
		records, extra, err = plugin.SRV(ctx, e, zone, state, opt)
	case dns.TypeSOA:
		records, err = plugin.SOA(ctx, e, zone, state, opt)
	case dns.TypeNS:
		if state.Name() == zone {
			records, extra, err = plugin.NS(ctx, e, zone, state, opt)
			break
		}
		fallthrough
	default:
		// Do a fake A lookup, so we can distinguish between NODATA and NXDOMAIN
		_, _, err = plugin.A(ctx, e, zone, state, nil, opt)
	}

	if err != nil && e.IsNameError(err) {
		if e.Fall.Through(state.Name()) {
			return plugin.NextOrFailure(e.Name(), e.Next, ctx, w, r)
		}
		return plugin.BackendError(ctx, e, zone, dns.RcodeNameError, state, nil /* err */, opt)
	}
	if err != nil {
		return plugin.BackendError(ctx, e, zone, dns.RcodeServerFailure, state, err, opt)
	}

	// Filter out encrypted records (those with 01:, 02:, or 03: prefixes)
	records = filterEncryptedRecords(records)

	if len(records) == 0 {
		return plugin.BackendError(ctx, e, zone, dns.RcodeSuccess, state, err, opt)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Truncated = truncated
	m.Authoritative = true
	m.Answer = records
	m.Extra = extra

	w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

// filterEncryptedRecords removes TXT records with encryption prefixes (01:, 02:, 03:)
func filterEncryptedRecords(records []dns.RR) []dns.RR {
	filtered := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		// Only filter TXT records
		if txt, ok := rr.(*dns.TXT); ok {
			// Check if any string in the TXT record has an encryption prefix
			hasEncryption := false
			for _, s := range txt.Txt {
				if strings.HasPrefix(s, "01:") || strings.HasPrefix(s, "02:") || strings.HasPrefix(s, "03:") {
					hasEncryption = true
					break
				}
			}
			// Skip encrypted TXT records
			if hasEncryption {
				continue
			}
		}
		filtered = append(filtered, rr)
	}
	return filtered
}

// handleWKDIBERequest handles WKDIBE encrypted record requests
func (e *Etcd) handleWKDIBERequest(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, state request.Request, zone string, opt plugin.Options) (int, error) {
	// Get encrypted record from standard etcd path
	services, err := e.Records(ctx, state, true)
	if err != nil {
		if e.IsNameError(err) {
			return plugin.BackendError(ctx, e, zone, dns.RcodeNameError, state, nil, opt)
		}
		return plugin.BackendError(ctx, e, zone, dns.RcodeServerFailure, state, err, opt)
	}

	if len(services) == 0 {
		return plugin.BackendError(ctx, e, zone, dns.RcodeNameError, state, nil, opt)
	}

	// Find the first service with encrypted text
	var encryptedText string
	for _, svc := range services {
		if svc.Text != "" {
			encryptedText = svc.Text
			break
		}
	}

	if encryptedText == "" {
		return plugin.BackendError(ctx, e, zone, dns.RcodeNameError, state, nil, opt)
	}

	// Validate encryption prefix
	if !strings.HasPrefix(encryptedText, "02:") {
		// Encryption type mismatch - requested WKDIBE but record is different type
		return plugin.BackendError(ctx, e, zone, dns.RcodeServerFailure, state,
			fmt.Errorf("encryption type mismatch: expected WKDIBE (02:)"), opt)
	}

	// Create TXT record with 255-byte splitting
	txtRecord := createTXTRecord(state.Name(), encryptedText, services[0].TTL)

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = []dns.RR{txtRecord}

	w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

// handleCalypsoRequest handles Calypso encrypted record requests with searchtag
func (e *Etcd) handleCalypsoRequest(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, state request.Request, zone string, searchtag string, opt plugin.Options) (int, error) {
	if searchtag == "" {
		return plugin.BackendError(ctx, e, zone, dns.RcodeServerFailure, state,
			fmt.Errorf("missing searchtag in Calypso request"), opt)
	}

	// Lookup using searchtag path: /skydns-calypso/<searchtag>
	path := fmt.Sprintf("/%s/%s", e.CalypsoPathPrefix, searchtag)

	resp, err := e.get(ctx, path, false)
	if err != nil {
		if e.IsNameError(err) {
			return plugin.BackendError(ctx, e, zone, dns.RcodeNameError, state, nil, opt)
		}
		return plugin.BackendError(ctx, e, zone, dns.RcodeServerFailure, state, err, opt)
	}

	if resp.Count == 0 {
		return plugin.BackendError(ctx, e, zone, dns.RcodeNameError, state, nil, opt)
	}

	// Parse the service from etcd value
	var svc msg.Service
	if err := json.Unmarshal(resp.Kvs[0].Value, &svc); err != nil {
		return plugin.BackendError(ctx, e, zone, dns.RcodeServerFailure, state,
			fmt.Errorf("failed to parse service: %w", err), opt)
	}

	if svc.Text == "" {
		return plugin.BackendError(ctx, e, zone, dns.RcodeNameError, state, nil, opt)
	}

	// Validate encryption prefix
	if !strings.HasPrefix(svc.Text, "03:") {
		// Encryption type mismatch - requested Calypso but record is different type
		return plugin.BackendError(ctx, e, zone, dns.RcodeServerFailure, state,
			fmt.Errorf("encryption type mismatch: expected Calypso (03:)"), opt)
	}

	// Create TXT record with 255-byte splitting
	txtRecord := createTXTRecord(state.Name(), svc.Text, svc.TTL)

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = []dns.RR{txtRecord}

	w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

// createTXTRecord creates a DNS TXT record, splitting content at 255-byte boundaries
func createTXTRecord(name, text string, ttl uint32) *dns.TXT {
	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
	}

	// Split text into 255-byte chunks for TXT record format
	const maxTXTLen = 255
	for len(text) > 0 {
		chunkSize := len(text)
		if chunkSize > maxTXTLen {
			chunkSize = maxTXTLen
		}
		txt.Txt = append(txt.Txt, text[:chunkSize])
		text = text[chunkSize:]
	}

	return txt
}

// Name implements the Handler interface.
func (e *Etcd) Name() string { return "etcd_calypso" }
