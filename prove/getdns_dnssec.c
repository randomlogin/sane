#include "getdns_dnssec.h"
#include "../getdns/getdns.h"
#include "../getdns/getdns_extra.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_dict(getdns_dict *dict)
{
  if (dict == NULL)
    printf("NULL\n");
  char *pretty_printed_dict = getdns_pretty_print_dict(dict);
  printf("%s\n", pretty_printed_dict);
  free(pretty_printed_dict);
}

void print_list(getdns_list *list)
{
  if (list == NULL)
    printf("NULL\n");
  char *pretty_printed_list = getdns_pretty_print_list(list);
  printf("%s\n", pretty_printed_list);
  free(pretty_printed_list);
}

//takes inpute wire data and the transforsm it to
int dns_wire_to_rr_dict_list(uint8_t **in_wire, size_t *in_wire_len, getdns_list *rr_list) {
  getdns_return_t r;
  getdns_dict *rr_dict;

  int idx = 0;

  while (*in_wire_len > 0) {
    if ((r = getdns_wire2rr_dict_scan(in_wire, in_wire_len, &rr_dict))) {
      fprintf(stderr, "wire to rr_dict failed: %d\n", r);
      for (size_t i = 0; i < *in_wire_len; i++) {
        printf("%02x ", (*in_wire)[i]);
      }
      rr_dict = NULL;
      return 1;
      break;
    }
    /* print_dict(rr_dict); */
    if ((r = getdns_list_set_dict(rr_list, idx++, rr_dict))) {
      fprintf(stderr, "setting rr_dict to list failed: %d\n", r);
      return 1;
    }
    rr_dict = NULL;
  }
  return 0;
}

uint8_t* read_binary_file(const char *filename, size_t *size) {
    FILE *file;
    uint8_t *buffer;
    long file_size;

    file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "Unable to open file %s\n", filename);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    rewind(file);

    buffer = (uint8_t *)malloc(file_size);
    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return NULL;
    }

    if (fread(buffer, 1, file_size, file) != file_size) {
        fprintf(stderr, "Failed to read file\n");
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);

    *size = file_size;
    return buffer;
}

int check_dnssec(uint8_t *dns_record_wire, size_t dns_record_wire_len) {
  uint8_t *dns_record_wire_ptr = dns_record_wire;

  getdns_return_t r = GETDNS_RETURN_GOOD; /* Holder for all function returns */
  getdns_dict *rr_dict;

  getdns_list *to_validate = getdns_list_create();
  getdns_list *chain_support = getdns_list_create();
  getdns_list *trust_anchors = getdns_list_create();

  uint8_t idx_to_validate = 0;
  uint8_t idx_support = 0;
  uint8_t idx_trust = 0;
  while (r == GETDNS_RETURN_GOOD && dns_record_wire_len > 0) {
    if ((r = getdns_wire2rr_dict_scan(&dns_record_wire_ptr, &dns_record_wire_len, &rr_dict))) {
      fprintf(stderr, "wire to rr_dict failed: %d\n", r);
      break;
    }
    uint32_t rr_type;
    if ((r = getdns_dict_get_int(rr_dict, "type", &rr_type)) != GETDNS_RETURN_GOOD) {
      fprintf(stderr, "extracting rr type failed: %d\n", r);
      return 1;
    }

    if (rr_type == GETDNS_RRTYPE_TLSA || rr_type == GETDNS_RRTYPE_NSEC) {
      if ((r = getdns_list_set_dict(to_validate, idx_to_validate++, rr_dict)) != GETDNS_RETURN_GOOD) {
        fprintf(stderr, "setting rr_dict to to_validate list failed: %d\n", r);
      }
    } else if (rr_type == GETDNS_RRTYPE_DS) {
        if ((r = getdns_list_set_dict(trust_anchors, idx_trust++, rr_dict)) != GETDNS_RETURN_GOOD) {
          fprintf(stderr, "setting RRSIG (covering TLSA) to to_validate list failed: %d\n", r);
        }
    }


    else if (rr_type == GETDNS_RRTYPE_RRSIG) {
      getdns_dict *rdata;
      uint32_t type_covered;
      if ((r = getdns_dict_get_dict(rr_dict, "rdata", &rdata)) != GETDNS_RETURN_GOOD) {
        fprintf(stderr, "extracting rdata from RRSIG failed: %d\n", r);
        return 1;
      }
      if ((r = getdns_dict_get_int(rdata, "type_covered", &type_covered)) != GETDNS_RETURN_GOOD) {
        fprintf(stderr, "extracting type_covered from RRSIG failed: %d\n", r);
        char *pretty_printed_dict = getdns_pretty_print_dict(rr_dict);
        printf("%s\n", pretty_printed_dict);
        free(pretty_printed_dict);
        return 1;
      }

      if (type_covered == GETDNS_RRTYPE_TLSA || type_covered == GETDNS_RRTYPE_NSEC) {
        if ((r = getdns_list_set_dict(to_validate, idx_to_validate++, rr_dict)) != GETDNS_RETURN_GOOD) {
          fprintf(stderr, "setting RRSIG (covering TLSA) to to_validate list failed: %d\n", r);
        }
      } else {
        if ((r = getdns_list_set_dict(chain_support, idx_support++, rr_dict)) != GETDNS_RETURN_GOOD) {
          fprintf(stderr, "setting RRSIG to chain_support list failed: %d\n", r);
        }
      }
    } else {
      if ((r = getdns_list_set_dict(chain_support, idx_support++, rr_dict)) != GETDNS_RETURN_GOOD) {
        fprintf(stderr, "setting rr_dict to chain_support list failed: %d\n", r);
      }
    }
    rr_dict = NULL;
  }

  /* printf("to_validate\n"); */
  /* print_list(to_validate); */
  /* printf("chain support\n"); */
  /* print_list(chain_support); */
  /*  */
  /*  */
  /* printf("trust anchors\n"); */
  /* print_list(trust_anchors); */

  if ((r = getdns_validate_dnssec2(to_validate, chain_support, trust_anchors, time(NULL), 500 * 30 * 24 * 60 * 60)) != GETDNS_DNSSEC_SECURE)
    fprintf(stderr, "validating dnssec failed: %d\n", r);
  else
    printf("Validated DNSSEC chain! r val %d \n", r);
  return r;
}

