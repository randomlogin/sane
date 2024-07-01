package prove

/*
#include "getdns_dnssec.h"
#include <getdns/getdns.h>
#cgo LDFLAGS: -L/usr/local/lib -lgetdns
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func GetdnsVerifyChain(recordWire []byte) error {

	dnsRecordWirePtr := (*C.uint8_t)(unsafe.Pointer(&recordWire[0]))
	result_code := C.validate_dnssec(dnsRecordWirePtr, C.size_t(len(recordWire)))
	switch result_code {

	case C.GETDNS_DNSSEC_SECURE:
		return nil
	case C.GETDNS_DNSSEC_BOGUS:
		return fmt.Errorf(C.GETDNS_DNSSEC_BOGUS_TEXT)
	case C.GETDNS_DNSSEC_INDETERMINATE:
		return fmt.Errorf(C.GETDNS_DNSSEC_INDETERMINATE_TEXT)
	case C.GETDNS_DNSSEC_INSECURE:
		return fmt.Errorf(C.GETDNS_DNSSEC_INSECURE_TEXT)
	default:
		return fmt.Errorf("could not verify dnssec chain")
	}
}
