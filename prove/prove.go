package prove

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/randomlogin/sane/debuglog"
	"github.com/randomlogin/sane/dnssec"
	"github.com/randomlogin/sane/sync"
	"golang.org/x/crypto/sha3"

	"github.com/nodech/go-hsd-utils/proof"
)

const urkelExt = "1.3.6.1.4.1.54392.5.1620"
const dnssecExt = "1.3.6.1.4.1.54392.5.1621"

type tlsError struct {
	err string
}

func (t *tlsError) Error() string {
	return t.err
}

func checkProof(certProof, certRoot, key []byte) (*int, error) {
	urkelProof, err := proof.NewFromBytes(certProof)
	if err != nil {
		return nil, fmt.Errorf("urkel verification: %s", err)
	}

	treeRoot := proof.UrkelHash(certRoot)
	urkelKey := proof.UrkelHash(key)
	resultCode, _ := urkelProof.Verify(treeRoot, urkelKey)
	if resultCode != proof.ProofOk {
		return nil, fmt.Errorf("urkel proof verification failed")
	}

	var buf bytes.Buffer
	err = urkelProof.Serialize(&buf)
	if err != nil {
		return nil, fmt.Errorf("serialization err: %s ", err)
	}
	var x = len(buf.Bytes())
	return &x, nil
}

func verifyUrkelExt(extensionValue []byte, domain string, roots []sync.BlockInfo) error {
	h := sha3.New256()
	h.Write([]byte(domain))
	key := h.Sum(nil)

	if len(extensionValue) == 0 {
		return fmt.Errorf("urkel extension is empty")
	}
	var numberOfProofs, i uint8 = extensionValue[0], 0
	if numberOfProofs == 0 {
		return fmt.Errorf("urkel extension is empty")
	}
	extensionValue = extensionValue[1:]
	for ; i < numberOfProofs; i++ {
		certRoot := extensionValue[:32] //Magic numbers, should be checked
		hexstr := hex.EncodeToString(certRoot)

		if len(extensionValue) < 32 {
			debuglog.Logger.Debug("urkel proof is empty")
			return fmt.Errorf("urkel data is corrupted")
		}
		certProof := extensionValue[32:]
		length, err := checkProof(certProof, certRoot, key)
		if err != nil {
			//found invalid proof
			debuglog.Logger.Debugf("urkel verification failed: %s", err)
			return err
		}
		for _, block := range roots {
			// found tree root among stored ones
			if hexstr == block.TreeRoot {
				debuglog.Logger.Debug("found tree root", hexstr, "from the certificate in the stored roots")
				return nil
			}
		}
		extensionValue = extensionValue[32+*length:]
		debuglog.Logger.Debug("could not find tree root", hexstr, "from the certificate in the stored roots")
	}
	return fmt.Errorf("could not find tree root in the stored ones")
}

// extracts proof data from the certificate then verifies if the proof is correct
func VerifyCertificateExtensions(roots []sync.BlockInfo, cert x509.Certificate, tlsa *dns.TLSA, externalServices []string) error {
	if len(cert.DNSNames) == 0 {
		return fmt.Errorf("certificate has empty dns names")
	}
	labels := dns.SplitDomainName(tlsa.Header().Name)
	if len(labels) < 3 {
		return fmt.Errorf("tlsa record has less than 3 labels")
	}
	tlsaDomain := strings.Join(labels[2:], ".")

	for _, domain := range cert.DNSNames {
		err := verifyDomain(tlsaDomain, cert, roots, tlsa, externalServices)
		if err == nil {
			debuglog.Logger.Debug("successfully verified certificate extensions for the domain " + domain)
			return nil
		}
		debuglog.Logger.Debugf("got error: %s during verification domain %s", err, domain)
	}
	return fmt.Errorf("failed to verify certificate extensions")
}

// verifyDomain is called to check every domain listed in the certificate
func verifyDomain(domain string, cert x509.Certificate, roots []sync.BlockInfo, tlsa *dns.TLSA, externalServices []string) error {
	var foundUrkel, foundDnssec bool
	var urkelExtension, dnssecExtension []byte
	var UrkelVerificationError, DNSSECVerificationError error = errors.New("urkel tree proof extension not found"), errors.New("DNSSEC chain extension not found")
	var err error
	var tld string
	labels := dns.SplitDomainName(domain)
	tld = labels[len(labels)-1]

	for _, elem := range cert.Extensions {
		if elem.Id.String() == urkelExt {
			foundUrkel = true
			urkelExtension = elem.Value
		}
		if elem.Id.String() == dnssecExt {
			foundDnssec = true
			dnssecExtension = elem.Value
		}
	}

	if !foundUrkel {
		if len(externalServices) == 0 {
			return fmt.Errorf("certificate does not have urkel proof extension and external service is disabled")
		}
		urkelExtension, err = fetchUrkel(domain, externalServices)
		if err != nil {
			debuglog.Logger.Debugf("failed to fetch DNSSEC data from %s for the domain %s: %s", externalServices, domain, err)
			return err
		}
	}

	if !foundDnssec {
		if len(externalServices) == 0 {
			return fmt.Errorf("certificate does not have dnssec chain extension and external service is disabled")
		}
		dnssecExtension, err = fetchDNSSEC(domain, externalServices)
		if err != nil {
			debuglog.Logger.Debugf("failed to fetch DNSSEC data from %s for the domain %s: %s", externalServices, domain, err)
			return err
		}
	}

	UrkelVerificationError = verifyUrkelExt(urkelExtension, tld, roots)
	if UrkelVerificationError != nil {
		debuglog.Logger.Debugf("failed to verify urkel proof: %s", UrkelVerificationError)
		return UrkelVerificationError
	}
	records, err := dnssec.ParseExt(dnssecExtension)
	if err != nil {
		debuglog.Logger.Debugf("failed to parse DNSSEC extension: %s", err)
		return err
	}

	DNSSECVerificationError = dnssec.VerifyDNSSECChain(records, domain, tlsa)
	if DNSSECVerificationError != nil {
		debuglog.Logger.Debugf("failed to verify DNSSEC chain: %s", DNSSECVerificationError)
		return DNSSECVerificationError
	}

	if (UrkelVerificationError == nil) && (DNSSECVerificationError == nil) {
		debuglog.Logger.Debug("DANE extensions from certificate are both valid")
		return nil
	} else {
		return fmt.Errorf("could not verify SANE for the domain %s: %s, %s", domain, UrkelVerificationError, DNSSECVerificationError)
	}
}

// Deprecated: using native golang implementation of urkel trees to verify
// func verifyUrkelExtC(extensionValue []byte, domain string, roots []sync.BlockInfo) error {
// 	h := sha3.New256()
// 	h.Write([]byte(domain))
// 	key := h.Sum(nil)
//
// 	certRoot := extensionValue[1 : 1+32] //Magic numbers, should be checked
// 	certProof := extensionValue[33:]
//
// 	proofResult := verifyUrkelProof(key, certProof, certRoot)
// 	if !proofResult {
// 		return fmt.Errorf("the proof in the certificate is not valid")
// 	}
//
// 	// check that root is one of the stored ones
// 	hexstr := hex.EncodeToString(certRoot)
// 	for _, block := range roots {
// 		if hexstr == block.TreeRoot {
// 			// log.Print("Found tree root ", block.TreeRoot, " from the certificate in the stored ones.")
// 			return nil
// 		}
// 	}
// 	return fmt.Errorf("urkel tree root %s from the certificate was not found among the stored ones", hexstr)
// }
//
// Deprecated: this version uses
// verifies key in the urkel tree with a given proof against a given root
// func verifyUrkelProof(key, proof, root []byte) bool {
// 	proofLen := C.size_t(len(proof))
// 	var exists C.int
// 	value := make([]byte, len(proof))
// 	var valueLen C.size_t
//
// 	intres := C.urkel_verify(
// 		&exists,
// 		(*C.uchar)(&value[0]),
// 		&valueLen,
// 		(*C.uchar)(&proof[0]),
// 		proofLen,
// 		(*C.uchar)(&key[0]),
// 		(*C.uchar)(&root[0]))
//
// 	if intres == 1 {
// 		return true
// 	} else {
// 		return false
// 	}
// }
