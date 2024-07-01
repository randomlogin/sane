package prove

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

// Parses data from certificate extension, returns a list of RRs
func ParseExt(extval []byte) ([]dns.RR, error) {
	var records []dns.RR
	off := 4 //4 bytes of non-relevant data, namely port and value (of what?)
	var rr dns.RR
	var err error

	// port := binary.BigEndian.Uint16(extval[:2])
	// log.Print(port)

	for off < len(extval) {
		rr, off, err = dns.UnpackRR(extval, off)
		if err != nil {
			return nil, fmt.Errorf("cannot parse record data from extension: %s ", err)
		}
		records = append(records, rr)
	}
	withoutDuplicates := dns.Dedup(records, nil)
	if len(records) != len(withoutDuplicates) {
		return nil, errors.New("extension data contains duplicate records")
	}
	return records, nil
}

func VerifyDNSSECChain(chainWireData []byte, domain string, dns_tlsa *dns.TLSA) error {
	records, err := ParseExt(chainWireData)
	if err != nil {
		// debuglog.Logger.Debugf("failed to parse DNSSEC extension: %s", err)
		return err
	}
	var tlsas []*dns.TLSA
	for i := 0; i < len(records); i++ {
		record := records[i]
		switch record.(type) {
		case *dns.TLSA:
			r := record.(*dns.TLSA)
			tlsas = append(tlsas, r)
		}
	}

	//checks if in DNSSEC chain there exists a TLSA record which equals to the one used in connection
	if !slices.ContainsFunc(tlsas, func(a *dns.TLSA) bool { return dns.IsDuplicate(a, dns_tlsa) }) {
		return fmt.Errorf("TLSA records from extension do not correspond to the server ones")
	}

	domainCovered := false
	for _, tlsa := range tlsas {
		tlsaLabels := dns.SplitDomainName(tlsa.Hdr.Name)
		if len(tlsaLabels) < 3 {
			return fmt.Errorf("TLSA records had less than 3 labels")
		}
		child := dns.Fqdn(strings.Join(tlsaLabels[2:], "."))
		if child == dns.Fqdn(domain) {
			domainCovered = true
			break
		}
	}

	if !domainCovered {
		return fmt.Errorf("no TLSA record covers the domain %s", domain)
	}

	return GetdnsVerifyChain(chainWireData[4:])
}
