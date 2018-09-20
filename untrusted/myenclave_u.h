#ifndef MYENCLAVE_U_H__
#define MYENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "../trusted/lib/classifier.h"
#include "../trusted/lib/ofproto-provider.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_MYENCLAVE_SAMPLE_DEFINED__
#define OCALL_MYENCLAVE_SAMPLE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_myenclave_sample, (const char* str));
#endif

sgx_status_t ecall_myenclave_sample(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_ofproto_init_tables(sgx_enclave_id_t eid, int n_tables);
sgx_status_t ecall_readonly_set(sgx_enclave_id_t eid, int table_id);
sgx_status_t ecall_istable_readonly(sgx_enclave_id_t eid, int* retval, uint8_t table_id);
sgx_status_t ecall_cls_rule_init(sgx_enclave_id_t eid, struct cls_rule* o_cls_rule, const struct match* match, unsigned int priority);
sgx_status_t ecall_cr_rule_overlaps(sgx_enclave_id_t eid, int* retval, int table_id, struct cls_rule* o_cls_rule);
sgx_status_t ecall_cls_rule_destroy(sgx_enclave_id_t eid, struct cls_rule* o_cls_rule);
sgx_status_t ecall_cls_rule_hash(sgx_enclave_id_t eid, uint32_t* retval, const struct cls_rule* o_cls_rule, uint32_t basis);
sgx_status_t ecall_cls_rule_equal(sgx_enclave_id_t eid, int* retval, const struct cls_rule* o_cls_rule_a, const struct cls_rule* o_cls_rule_b);
sgx_status_t ecall_classifier_replace(sgx_enclave_id_t eid, int table_id, struct cls_rule* o_cls_rule, struct cls_rule** cls_rule_rtrn);
sgx_status_t ecall_rule_get_flags(sgx_enclave_id_t eid, enum oftable_flags* retval, int table_id);
sgx_status_t ecall_cls_count(sgx_enclave_id_t eid, int* retval, int table_id);
sgx_status_t ecall_eviction_fields_enable(sgx_enclave_id_t eid, int* retval, int table_id);
sgx_status_t ecall_evg_group_resize(sgx_enclave_id_t eid, int table_id, struct cls_rule* o_cls_rule, size_t priority);
sgx_status_t ecall_evg_add_rule(sgx_enclave_id_t eid, size_t* retval, int table_id, struct cls_rule* o_cls_rule, uint32_t priority, uint32_t rule_evict_prioriy, struct heap_node rule_evg_node);
sgx_status_t ecall_evg_remove_rule(sgx_enclave_id_t eid, int* retval, int table_id, struct cls_rule* o_cls_rule);
sgx_status_t ecall_cls_remove(sgx_enclave_id_t eid, int table_id, struct cls_rule* o_cls_rule);
sgx_status_t ecall_choose_rule_to_evict(sgx_enclave_id_t eid, int table_id, struct cls_rule* o_cls_rule);
sgx_status_t ecall_table_mflows(sgx_enclave_id_t eid, unsigned int* retval, int table_id);
sgx_status_t ecall_choose_rule_to_evict_p(sgx_enclave_id_t eid, int table_id, struct cls_rule* o_cls_rule);
sgx_status_t ecall_minimatch_expand(sgx_enclave_id_t eid, struct cls_rule* o_cls_rule, struct match* dst);
sgx_status_t ecall_cr_priority(sgx_enclave_id_t eid, unsigned int* retval, struct cls_rule* o_cls_rule);
sgx_status_t ecall_cls_find_match_exactly(sgx_enclave_id_t eid, int table_id, const struct match* target, unsigned int priority, struct cls_rule** o_cls_rule);
sgx_status_t ecall_femt_ccfe_c(sgx_enclave_id_t eid, int* retval, int ofproto_n_tables, uint8_t table_id, const struct match* match);
sgx_status_t ecall_femt_ccfe_r(sgx_enclave_id_t eid, int ofproto_n_tables, struct cls_rule** buf, int elem, uint8_t table_id, const struct match* match);
sgx_status_t ecall_femt_c(sgx_enclave_id_t eid, int* retval, int ofproto_n_tables, uint8_t table_id, const struct match* match, unsigned int priority);
sgx_status_t ecall_femt_r(sgx_enclave_id_t eid, int ofproto_n_tables, struct cls_rule** buf, int elem, uint8_t table_id, const struct match* match, unsigned int priority);
sgx_status_t ecall_oftable_enable_eviction(sgx_enclave_id_t eid, int table_id, const struct mf_subfield* fields, size_t n_fields, uint32_t random_v);
sgx_status_t ecall_oftable_disable_eviction(sgx_enclave_id_t eid, int table_id);
sgx_status_t ecall_ccfe_c(sgx_enclave_id_t eid, int* retval, int table_id);
sgx_status_t ecall_ccfe_r(sgx_enclave_id_t eid, struct cls_rule** buf, int elem, int table_id);
sgx_status_t ecall_table_mflows_set(sgx_enclave_id_t eid, int table_id, unsigned int value);
sgx_status_t ecall_ofproto_destroy(sgx_enclave_id_t eid);
sgx_status_t ecall_total_rules(sgx_enclave_id_t eid, unsigned int* retval);
sgx_status_t ecall_table_name(sgx_enclave_id_t eid, int table_id, char* buf, size_t len);
sgx_status_t ecall_collect_ofmonitor_util_c(sgx_enclave_id_t eid, int* retval, int ofproto_n_tables, int table_id, const struct minimatch* match);
sgx_status_t ecall_collect_ofmonitor_util_r(sgx_enclave_id_t eid, int ofproto_n_tables, struct cls_rule** buf, int elem, int table_id, const struct minimatch* match);
sgx_status_t ecall_cls_rule_is_loose_match(sgx_enclave_id_t eid, int* retval, struct cls_rule* o_cls_rule, const struct minimatch* criteria);
sgx_status_t ecall_fet_ccfes_c(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_fet_ccfes_r(sgx_enclave_id_t eid, struct cls_rule** buf, int elem);
sgx_status_t ecall_fet_ccfe_c(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_fet_ccfe_r(sgx_enclave_id_t eid, struct cls_rule** buf, int elem);
sgx_status_t ecall_cls_lookup(sgx_enclave_id_t eid, struct cls_rule** o_cls_rule, int table_id, const struct flow* flow, struct flow_wildcards* wc);
sgx_status_t ecall_cls_rule_priority(sgx_enclave_id_t eid, unsigned int* retval, struct cls_rule* o_cls_rule);
sgx_status_t ecall_desfet_ccfes_c(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_desfet_ccfes_r(sgx_enclave_id_t eid, struct cls_rule** buf, int elem);
sgx_status_t ecall_cls_rule_format(sgx_enclave_id_t eid, unsigned int* retval, const struct cls_rule* o_cls_rule, struct match* megamatch);
sgx_status_t ecall_miniflow_expand(sgx_enclave_id_t eid, struct cls_rule* o_cls_rule, struct flow* flow);
sgx_status_t ecall_rule_calculate_tag(sgx_enclave_id_t eid, uint32_t* retval, struct cls_rule* o_cls_rule, const struct flow* flow, int table_id);
sgx_status_t ecall_SGX_table_dpif(sgx_enclave_id_t eid, int n_tables);
sgx_status_t ecall_table_update_taggable(sgx_enclave_id_t eid, int* retval, uint8_t table_id);
sgx_status_t ecall_is_sgx_other_table(sgx_enclave_id_t eid, int* retval, int id);
sgx_status_t ecall_rule_calculate_tag_s(sgx_enclave_id_t eid, uint32_t* retval, int id, const struct flow* flow, uint32_t secret);
sgx_status_t ecall_hidden_tables_check(sgx_enclave_id_t eid);
sgx_status_t ecall_oftable_set_name(sgx_enclave_id_t eid, int table_id, char* name);
sgx_status_t ecall_minimask_get_vid_mask(sgx_enclave_id_t eid, uint16_t* retval, struct cls_rule* o_cls_rule);
sgx_status_t ecall_miniflow_get_vid(sgx_enclave_id_t eid, uint16_t* retval, struct cls_rule* o_cls_rule);
sgx_status_t ecall_ofproto_get_vlan_c(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_ofproto_get_vlan_r(sgx_enclave_id_t eid, uint16_t* buf, int elem);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
