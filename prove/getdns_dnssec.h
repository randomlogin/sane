#ifndef DNSSEC_H
#define DNSSEC_H

#include <stdint.h>
#include <stddef.h> // For size_t

int validate_dnssec(uint8_t *dns_record_wire, size_t dns_record_wire_len);

#endif // DNSSEC_H
