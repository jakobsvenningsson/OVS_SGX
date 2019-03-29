#ifndef _HELPERS_H_
#define _HELPERS_H_

#include "enclave.h"
#include "hmap.h"
#include "classifier.h"
#include "ofproto-provider.h"


void sgx_table_cls_init();
struct sgx_cls_rule* node_search(const struct cls_rule *out);
struct sgx_cls_rule* node_search_evict(struct eviction_group *out);
struct sgx_cls_rule* node_insert(uint32_t hash);
void node_delete(struct cls_rule *out);

#endif
