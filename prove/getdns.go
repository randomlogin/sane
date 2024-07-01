package prove

/*
#include "getdns_dnssec.h"
#include <getdns/getdns.h>
#cgo LDFLAGS: -L/usr/local/lib -lgetdns
*/
import "C"
import (
	"fmt"
	"log"
	"unsafe"
)

var domain = "theshake"

func GetdnsVerifyChain(recordWire []byte) error {
	var err error

	dnsRecordWirePtr := (*C.uint8_t)(unsafe.Pointer(&recordWire[0]))

	// Call the C function
	result_code := C.check_dnssec(dnsRecordWirePtr, C.size_t(len(recordWire)))
	log.Print("the result is ", result_code)
	if result_code == C.GETDNS_DNSSEC_SECURE {
		err = nil
	}
	if result_code == C.GETDNS_DNSSEC_BOGUS {
		err = fmt.Errorf(C.GETDNS_DNSSEC_BOGUS_TEXT)
	}
	if result_code == C.GETDNS_DNSSEC_INDETERMINATE {
		err = fmt.Errorf(C.GETDNS_DNSSEC_INDETERMINATE_TEXT)
	}
	if result_code == C.GETDNS_DNSSEC_INSECURE {
		err = fmt.Errorf(C.GETDNS_DNSSEC_INSECURE_TEXT)
	}

	return err

}
