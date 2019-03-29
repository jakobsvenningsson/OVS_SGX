#ifndef MYENCLAVE_T_H__
#define MYENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "common.h"
#include "../trusted/lib/classifier.h"
#include "../trusted/lib/ofproto-provider.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_start_poller(async_ecall* data);
int ecall_myenclave_sample(void);
void ecall_ofproto_init_tables(int n_tables);
void ecall_readonly_set(int table_id);
int ecall_istable_readonly(uint8_t table_id);
void ecall_cls_rule_init(struct cls_rule* o_cls_rule, const struct match* match, unsigned int priority);
int ecall_cr_rule_overlaps(int table_id, struct cls_rule* o_cls_rule);
void ecall_cls_rule_destroy(struct cls_rule* o_cls_rule);
uint32_t ecall_cls_rule_hash(const struct cls_rule* o_cls_rule, uint32_t basis);
int ecall_cls_rule_equal(const struct cls_rule* o_cls_rule_a, const struct cls_rule* o_cls_rule_b);
void ecall_classifier_replace(int table_id, struct cls_rule* o_cls_rule, struct cls_rule** cls_rule_rtrn);
enum oftable_flags ecall_rule_get_flags(int table_id);
int ecall_cls_count(int table_id);
int ecall_eviction_fields_enable(int table_id);
void ecall_evg_group_resize(int table_id, struct cls_rule* o_cls_rule, size_t priority);
size_t ecall_evg_add_rule(int table_id, struct cls_rule* o_cls_rule, uint32_t priority, uint32_t rule_evict_prioriy, struct heap_node rule_evg_node);
int ecall_evg_remove_rule(int table_id, struct cls_rule* o_cls_rule);
void ecall_cls_remove(int table_id, struct cls_rule* o_cls_rule);
void ecall_choose_rule_to_evict(int table_id, struct cls_rule* o_cls_rule);
unsigned int ecall_table_mflows(int table_id);
void ecall_choose_rule_to_evict_p(int table_id, struct cls_rule* o_cls_rule);
void ecall_minimatch_expand(struct cls_rule* o_cls_rule, struct match* dst);
unsigned int ecall_cr_priority(struct cls_rule* o_cls_rule);
void ecall_cls_find_match_exactly(int table_id, const struct match* target, unsigned int priority, struct cls_rule** o_cls_rule);
int ecall_femt_ccfe_c(int ofproto_n_tables, uint8_t table_id, const struct match* match);
void ecall_femt_ccfe_r(int ofproto_n_tables, struct cls_rule** buf, int elem, uint8_t table_id, const struct match* match);
int ecall_femt_c(int ofproto_n_tables, uint8_t table_id, const struct match* match, unsigned int priority);
void ecall_femt_r(int ofproto_n_tables, struct cls_rule** buf, int elem, uint8_t table_id, const struct match* match, unsigned int priority);
void ecall_oftable_enable_eviction(int table_id, const struct mf_subfield* fields, size_t n_fields, uint32_t random_v);
void ecall_oftable_disable_eviction(int table_id);
int ecall_ccfe_c(int table_id);
void ecall_ccfe_r(struct cls_rule** buf, int elem, int table_id);
void ecall_table_mflows_set(int table_id, unsigned int value);
void ecall_ofproto_destroy(void);
unsigned int ecall_total_rules(void);
void ecall_table_name(int table_id, char* buf, size_t len);
int ecall_collect_ofmonitor_util_c(int ofproto_n_tables, int table_id, const struct minimatch* match);
void ecall_collect_ofmonitor_util_r(int ofproto_n_tables, struct cls_rule** buf, int elem, int table_id, const struct minimatch* match);
int ecall_cls_rule_is_loose_match(struct cls_rule* o_cls_rule, const struct minimatch* criteria);
int ecall_fet_ccfes_c(void);
void ecall_fet_ccfes_r(struct cls_rule** buf, int elem);
int ecall_fet_ccfe_c(void);
void ecall_fet_ccfe_r(struct cls_rule** buf, int elem);
void ecall_cls_lookup(struct cls_rule** o_cls_rule, int table_id, const struct flow* flow, struct flow_wildcards* wc);
unsigned int ecall_cls_rule_priority(struct cls_rule* o_cls_rule);
int ecall_desfet_ccfes_c(void);
void ecall_desfet_ccfes_r(struct cls_rule** buf, int elem);
unsigned int ecall_cls_rule_format(const struct cls_rule* o_cls_rule, struct match* megamatch);
void ecall_miniflow_expand(struct cls_rule* o_cls_rule, struct flow* flow);
uint32_t ecall_rule_calculate_tag(struct cls_rule* o_cls_rule, const struct flow* flow, int table_id);
void ecall_SGX_table_dpif(int n_tables);
int ecall_table_update_taggable(uint8_t table_id);
int ecall_is_sgx_other_table(int id);
uint32_t ecall_rule_calculate_tag_s(int id, const struct flow* flow, uint32_t secret);
void ecall_hidden_tables_check(void);
void ecall_oftable_set_name(int table_id, char* name);
uint16_t ecall_minimask_get_vid_mask(struct cls_rule* o_cls_rule);
uint16_t ecall_miniflow_get_vid(struct cls_rule* o_cls_rule);
int ecall_ofproto_get_vlan_c(void);
void ecall_ofproto_get_vlan_r(uint16_t* buf, int elem);

sgx_status_t SGX_CDECL ocall_myenclave_sample(const char* str);
sgx_status_t SGX_CDECL ocall_sleep(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
