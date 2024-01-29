package prove

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"log/slog"

	"github.com/miekg/dns"
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

func verifyUrkelExt(extensionValue []byte, domain string, roots []sync.BlockInfo) error {
	h := sha3.New256()
	h.Write([]byte(domain))
	key := h.Sum(nil)

	certRoot := extensionValue[1 : 1+32] //Magic numbers, should be checked
	certProof := extensionValue[33:]

	// log.Print(hex.EncodeToString(certProof))
	urkelProof, err := proof.NewFromBytes(certProof)
	if err != nil {
		return fmt.Errorf("urkel verification: %s", err)
	}

	treeRoot := proof.UrkelHash(certRoot)
	urkelKey := proof.UrkelHash(key)
	resultCode, _ := urkelProof.Verify(treeRoot, urkelKey)
	if resultCode != proof.ProofOk {
		return fmt.Errorf("urkel proof verification failed for TLD %s", domain)
	}

	// check that root is one of the stored ones
	hexstr := hex.EncodeToString(certRoot)
	for _, block := range roots {
		if hexstr == block.TreeRoot {
			slog.Debug("Found tree root ", block.TreeRoot, " from the certificate in the stored roots")
			return nil
		}
	}
	return fmt.Errorf("urkel tree root %s from the certificate was not found among the stored ones", hexstr)
}

// extracts proof data from the certificate then verifies if the proof is correct
func VerifyCertificateExtensions(roots []sync.BlockInfo, cert x509.Certificate, tlsa *dns.TLSA) error {
	extensions := cert.Extensions
	if len(extensions) < 2 {
		return fmt.Errorf("not found enough extensions in the certificate")
	}
	if len(cert.DNSNames) == 0 {
		return fmt.Errorf("certificate has empty dns names")
	}

	for _, domain := range cert.DNSNames {
		err := verifyDomain(domain, cert, roots, tlsa)
		if err == nil {
			slog.Debug("successfully verified certificate extensions for domain " + domain)
			return nil
		}
		slog.Debug("got error %s verifying domain %s", err, domain)
	}
	return fmt.Errorf("failed to verify certificate extensions")
}

func verifyDomain(domain string, cert x509.Certificate, roots []sync.BlockInfo, tlsa *dns.TLSA) error {
	labels := dns.SplitDomainName(domain)
	tld := labels[len(labels)-1]

	var UrkelVerificationError, DNSSECVerificationError error = errors.New("urkel tree proof extension not found"), errors.New("DNSSEC chain extension not found")
	//if does not contain dnssecExt:
	var foundUrkel, foundDnssec bool
	for _, elem := range cert.Extensions {
		if elem.Id.String() == urkelExt {
			foundUrkel = true
		}
		if elem.Id.String() == dnssecExt {
			foundDnssec = true
		}
	}

	// if !foundUrkel {
	log.Print("yo ", tld)
	urkel, err := fetchUrkel(domain)
	if err != nil {
		log.Print(err)
		return err
	}
	log.Print("got urkel from external")
	UrkelVerificationError = verifyUrkelExt(urkel, tld, roots)
	if UrkelVerificationError != nil {
		log.Print("UrkelVerificationError", UrkelVerificationError, domain)
		return UrkelVerificationError
	}

	// }
	log.Print(foundDnssec, foundUrkel)

	if !foundDnssec {
		log.Print("yo")
		qwe, err := fetchDNSSEC(domain)
		if err != nil {
			log.Print(err)
			return err
		}
		records, err := dnssec.ParseExt(qwe)
		if err != nil {
			log.Print(err)
			return err
		}
		log.Print("got records from external")
		DNSSECVerificationError = dnssec.VerifyDNSSECChain(records, domain, tlsa)
		if DNSSECVerificationError != nil {
			log.Print("DNSSECVerificationError", DNSSECVerificationError, domain)
			return DNSSECVerificationError
		}

	}

	for _, elem := range cert.Extensions {
		slog.Debug("found an extenson in certificate, its id is ", elem.Id.String())
		if elem.Id.String() == urkelExt {
			UrkelVerificationError = verifyUrkelExt(elem.Value, tld, roots)
			if UrkelVerificationError != nil {
				slog.Debug("UrkelVerificationError", UrkelVerificationError, domain)
				return UrkelVerificationError
			}
		}
		if elem.Id.String() == dnssecExt {

			records, err := dnssec.GetRecordsFromCertificate(cert)
			if err != nil {
				return err
			}
			DNSSECVerificationError = dnssec.VerifyDNSSECChain(records, domain, tlsa)
			if DNSSECVerificationError != nil {
				slog.Debug("DNSSECVerificationError", DNSSECVerificationError, domain)
				return DNSSECVerificationError
			}
		}
	}

	if (UrkelVerificationError == nil) && (DNSSECVerificationError == nil) {
		slog.Debug("DANE extensions from certificate are both valid")
		return nil
	} else {
		return fmt.Errorf("could not verify SANE for domain %s: %s, %s", domain, UrkelVerificationError, DNSSECVerificationError)
	}

}

// Deprecated: using native golang implementation of urkel trees to verify
// func verifyUrkelExt(extensionValue []byte, domain string, roots []sync.BlockInfo) error {
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
