package dnssec

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"slices"
	"sort"

	"github.com/miekg/dns"
)

const dnssecExt = "1.3.6.1.4.1.54392.5.1621"
const rootKey = ". 10 IN DNSKEY 257 3 13 T9cURJ2M/Mz9q6UsZNY+Ospyvj+Uv+tgrrWkLtPQwgU/Xu5Yk0l02Sn5ua2xAQfEYIzRO6v5iA+BejMeEwNP4Q=="

//TODO split code into smaller functions
//TODO check function arguments, set them to pointers where possible
//TODO verify the dependencies, remove the unused ones
//TODO add several TLSA records support (so rrsig would be a valid one)

func parseRootKey() *dns.DNSKEY {
	rr, err := dns.NewRR(rootKey)
	if err != nil {
		err := fmt.Errorf("error reading root zone DNSKEY %s", err)
		fmt.Print(err.Error())
		return nil
	}
	dnsKey := rr.(*dns.DNSKEY)
	return dnsKey
}

func ParseExt(extval []byte) ([]dns.RR, error) {
	var records []dns.RR
	off := 4 //4 bytes of non-relevant data, namely port and value (of what?)
	var rr dns.RR
	var err error
	// data := ext.Value

	port := binary.BigEndian.Uint16(extval[:2])
	log.Print(port)

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

// getRecordsFromCertificate returns records from certificate's dnssec extensions, the output is sorted by domain name, ascending
// for example: "_443._tcp.domain.", "domain.", ".", it does not impose any assumptions on records or certificate
func GetRecordsFromCertificate(cert x509.Certificate) ([]dns.RR, error) {
	var records []dns.RR
	for _, ext := range cert.Extensions {
		if ext.Id.String() == dnssecExt {
			off := 4 //4 bytes of non-relevant data, namely port and value (of what?)
			var rr dns.RR
			var err error
			data := ext.Value

			port := binary.BigEndian.Uint16(data[:2])
			log.Print(port)

			for off < len(data) {
				rr, off, err = dns.UnpackRR(data, off)
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
	}
	return nil, errors.New("could not find the right certificate extension")
}

// TODO distinguish KSK and ZSK
// expects the records to be sorted by domain name length descending (root zone is the last)
func VerifyDNSSECChain(records []dns.RR, domain string, dns_tlsa *dns.TLSA) error {

	var tlsas []*dns.TLSA
	var dss []*dns.DS
	var rrsigs []*dns.RRSIG
	var dnskeys []*dns.DNSKEY
	less := func(a, b int) bool { return !isStrictParentDomain(&records[a], &records[b]) }
	sort.Slice(records, less)
	// myprintslice(records)

	for i := 0; i < len(records); i++ {
		record := records[i]
		switch record.(type) {
		case *dns.TLSA:
			r := record.(*dns.TLSA)
			tlsas = append(tlsas, r)
		case *dns.DS:
			r := record.(*dns.DS)
			dss = append(dss, r)
		case *dns.RRSIG:
			r := record.(*dns.RRSIG)
			rrsigs = append(rrsigs, r)
		case *dns.DNSKEY:
			r := record.(*dns.DNSKEY)
			dnskeys = append(dnskeys, r)
		default:
			return errors.New("found a record which is neither TLSA, nor DS, nor RRSIG, nor DNSKEY, aborting")
		}
	}

	//checks if in DNSSEC chain there exists a TLSA record which equals to the one used in connection
	if !slices.ContainsFunc(tlsas, func(a *dns.TLSA) bool { return dns.IsDuplicate(a, dns_tlsa) }) {
		return fmt.Errorf("TLSA records from extension do not correspond to the server ones")
	}

	//iterating through all records to return a slice of slices, they represent levels, it means
	//there is a distinct level for each label in the domain, one level for the root zone, one for the top level domain and so on
	//we don't need to check that all other domains are parents of tlsa, as it follows from the correctness of dnssec
	//chain verification
	slices.Reverse(records)
	var levels []([]dns.RR)
	var j int //last level to which i've added elements
	for i, rec := range records {
		if i == 0 {
			levels = append(levels, []dns.RR{rec})
			continue
		}
		if i == len(records)-1 {
			levels[j] = append(levels[j], rec)
			break
		}
		if isStrictParentDomain(&rec, &(records[i+1])) {
			levels[j] = append(levels[j], rec)
			j = j + 1
			levels = append(levels, []dns.RR{})
		} else {
			levels[j] = append(levels[j], rec)
		}
	}

	if len(levels) <= 1 {
		return errors.New("found not enough levels of records")
	}

	//handling of the root zone
	//taking root trust anchor from the topmost level
	rootDNSKEY, err := findRootDNSKEY(levels[0])
	if err != nil {
		return err
	}

	//take all DNSKEY records from the rootzone, they are used to verify root RRSIG
	var rootZoneKeys []*dns.DNSKEY
	var rootRRSIG *dns.RRSIG

	for _, record := range levels[0] {
		dnskey, ok := record.(*dns.DNSKEY)
		if ok {
			rootZoneKeys = append(rootZoneKeys, dnskey)
			continue
		}
		rootRRSIG, ok = record.(*dns.RRSIG)
		if ok {
			if rootRRSIG.TypeCovered != dns.TypeDNSKEY {
				return fmt.Errorf("found root RRSIG corresponding not to DNSKEY, but to the record %s", rootRRSIG)
			}
		}
	}
	if rootRRSIG == nil {
		return errors.New("could not find root zone RRSIG")
	}

	var rootzonerrset []dns.RR
	for _, ds := range rootZoneKeys {
		rootzonerrset = append(rootzonerrset, ds)
	}

	if !dns.IsRRset(rootzonerrset) {
		return errors.New("DNSKEYS do not form a valid RRset")
	}

	//verifies root rrsig using root dns key
	err = rootRRSIG.Verify(rootDNSKEY, rootzonerrset)
	if err != nil {
		return err
	}
	//root zone is verified

	//so now we can go to the main loop of taking DS, then DNSKEY and then go further
	parents := rootZoneKeys
	for _, level := range levels[1:] {
		parents, err = verifyLevel(level, parents)
		if err != nil {
			return err
		}
	}
	return nil
}

// keys for the next level are output
func verifyLevel(level []dns.RR, parentKeys []*dns.DNSKEY) ([]*dns.DNSKEY, error) {
	var tlsas []*dns.TLSA
	var dss []*dns.DS
	var rrsigs []*dns.RRSIG
	var dnskeys []*dns.DNSKEY

	//splitting records by their type
	for _, record := range level {
		switch record.(type) {
		case *dns.TLSA:
			r := record.(*dns.TLSA)
			tlsas = append(tlsas, r)
		case *dns.DS:
			r := record.(*dns.DS)
			dss = append(dss, r)
		case *dns.RRSIG:
			r := record.(*dns.RRSIG)
			rrsigs = append(rrsigs, r)
		case *dns.DNSKEY:
			r := record.(*dns.DNSKEY)
			dnskeys = append(dnskeys, r)
		default:
			return nil, errors.New("found a record which is neither TLSA, nor DS, nor RRSIG, nor DNSKEY")
		}
	}

	if len(tlsas) != 0 {
		var tlsas_rr []dns.RR
		for _, tlsa := range tlsas {
			tlsas_rr = append(tlsas_rr, (dns.RR(tlsa)))
		}
		for _, rrsig_tlsa := range rrsigs {
			if rrsig_tlsa.TypeCovered == dns.TypeTLSA {
				err := verifyRRSIGWithDNSKEYs(parentKeys, rrsig_tlsa, tlsas_rr)
				if err != nil {
					return nil, err
				}
			}
		}
		//it's the last level, we don't have DNSKEYs there
		return nil, nil
	}

	//DS handling
	//if i have DS it should have rrsig which is signed by parent key
	if len(dss) != 0 {
		var rrs []dns.RR
		for _, ds := range dss {
			rrs = append(rrs, ds)
		}
		for _, rrsig_ds := range rrsigs {
			if rrsig_ds.TypeCovered == dns.TypeDS {
				err := verifyRRSIGWithDNSKEYs(parentKeys, rrsig_ds, rrs)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	//DNSKEY handling
	//if there is a DNSKEY it should have RRSIG signed by this ZSK, it also should have corresponding DS record
	if len(dnskeys) != 0 {
		var rrs []dns.RR
		for _, dnskey := range dnskeys {
			rrs = append(rrs, dnskey)
			dnskeyToDSed := dnskey.ToDS(dns.SHA256)
			var dnsHasDS bool
			for _, ds := range dss {
				dnsHasDS = dnsHasDS || dns.IsDuplicate(dnskeyToDSed, ds)
			}
			if !dnsHasDS {
				return nil, errors.New("could not find correct DS record for all DNSKEY records")
			}

		}
		for _, rrsigDNSKEY := range rrsigs {
			if rrsigDNSKEY.TypeCovered == dns.TypeDNSKEY {
				err := verifyRRSIGWithDNSKEYs(dnskeys, rrsigDNSKEY, rrs)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	return dnskeys, nil
}

// exclusive compare which return false of the domains are equal
func isStrictParentDomain(parent, child *dns.RR) bool {
	parentLabel := (*parent).Header().Name
	childLabel := (*child).Header().Name
	if parentLabel == childLabel {
		return false
	}
	return dns.IsSubDomain(parentLabel, childLabel)
}

// debug
func myprintslice(qq []dns.RR) {
	for _, x := range qq {
		fmt.Println(x.Header(), " ")
	}
}

// findRootDNSKEY verifies that root key (global constant) exists in the provided slice of dns.DNSKEY, returns it if successful
func findRootDNSKEY(keys []dns.RR) (*dns.DNSKEY, error) {
	rootKey := parseRootKey()
	for _, dnskey := range keys {
		if dns.IsDuplicate(dnskey, rootKey) {
			return rootKey, nil
		}
	}
	return nil, errors.New("could not find root DNSKEY")
}

// takes a slice of dnskeys and an RRSIG and tries to verify rrsig using that key
func verifyRRSIGWithDNSKEYs(dnskeys []*dns.DNSKEY, rrsig *dns.RRSIG, rrs []dns.RR) error {
	ok := dns.IsRRset(rrs)
	if !ok {
		return fmt.Errorf("provided records do not form correct RRset")
	}
	for _, DNSKey := range dnskeys {
		err := rrsig.Verify(DNSKey, rrs)
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("could not verify RRSIG for the type %s using provided DNSKEYs", dns.TypeToString[rrsig.TypeCovered])

}
