#ifndef _APP_H_
#define _APP_H_
#include <stdint.h>
/* API untrusted functions to trusted inside the enclave */
struct match;
struct cls_rule;
struct heap_node;
struct match;
struct mf_subfield;
struct minimatch;
struct flow;
struct flow_wildcards;

//for testing
struct rul *out;
///

int sgx_ofproto_init_tables(int n_tables);
void SGX_readonly_set(int table_id);
int SGX_istable_readonly(uint8_t table_id);
void SGX_cls_rule_init(struct cls_rule * o_cls_rule,
		const struct match * match , unsigned int priority);
int SGX_cr_rule_overlaps(int table_id,struct cls_rule * o_cls_rule);
void SGX_cls_rule_destroy(struct cls_rule *o_cls_rule);
int SGX_cls_rule_equal(const struct cls_rule *o_cls_rule_a,
		const struct cls_rule *o_cls_rule_b);
uint32_t SGX_cls_rule_hash(const struct cls_rule *o_cls_rule, uint32_t basis);
void SGX_classifier_replace(int table_id,struct cls_rule* o_cls_rule,struct cls_rule ** cls_rule_rtrn);
enum oftable_flags SGX_rule_get_flags (int table_id);
int SGX_cls_count(int table_id);
int SGX_eviction_fields_enable(int table_id);
void SGX_table_mflows_set(int table_id,unsigned int value);
size_t SGX_evg_add_rule(int table_id, struct cls_rule *o_cls_rule,uint32_t priority,
		uint32_t rule_evict_prioriy,struct heap_node rule_evg_node);
void SGX_evg_group_resize(int table_id,struct cls_rule *o_cls_rule,size_t priority);
int SGX_evg_remove_rule(int table_id,struct cls_rule *o_cls_rule);
void SGX_cls_remove(int table_id,struct cls_rule *o_cls_rule);
void SGX_choose_rule_to_evict(int table_id,struct cls_rule *o_cls_rule);
unsigned int SGX_table_mflows(int table_id);
void SGX_choose_rule_to_evict_p(int table_id,struct cls_rule *o_cls_rule);

void SGX_minimatch_expand(struct cls_rule *o_cls_rule,struct match *dst);
unsigned int SGX_cr_priority(struct cls_rule *o_cls_rule);
void sgx_oftable_check_hidden(void);
void SGX_cls_find_match_exactly(int table_id,
		const struct match *target,
		unsigned int priority,struct cls_rule **o_cls_rule);

int SGX_femt_ccfe_c(int ofproto_n_tables,uint8_t table_id,const struct match *match);
void SGX_femt_ccfe_r(int ofproto_n_tables,struct cls_rule **buf,int elem,uint8_t table_id,const struct match *match);
int SGX_ecall_femt_c(int ofproto_n_tables,uint8_t table_id,const struct match *match,unsigned int priority);
void SGX_ecall_femt_r(int ofproto_n_tables,struct cls_rule **buf,int elem,uint8_t table_id,const struct match *match,unsigned int priority);






int SGX_ccfe_c(int table_id);
void SGX_ccfe_r(struct cls_rule **buf,int elem,int table_id);
void SGX_oftable_enable_eviction(int table_id,const struct mf_subfield *fields,size_t n_fields,uint32_t random_v);
void SGX_oftable_disable_eviction(int table_id);

void SGX_ofproto_destroy(void);
unsigned int SGX_total_rules(void);
void SGX_table_name(int table_id,char *buf,size_t len);
int SGX_collect_ofmonitor_util_c(int ofproto_n_tables,int table_id,const struct minimatch *match);
void SGX_collect_ofmonitor_util_r(int ofproto_n_tables,struct cls_rule **buf,int elem,int table_id,const struct minimatch *match);
int SGX_cls_rule_is_loose_match(struct cls_rule *o_cls_rule,const struct minimatch *criteria);
int SGX_fet_ccfes_c(void);
void SGX_fet_ccfes_r(struct cls_rule **buf,int elem);

int SGX_fet_ccfe_c(void);
void SGX_fet_ccfe_r(struct cls_rule **buf,int elem);

void SGX_cls_lookup(struct cls_rule **o_cls_rule,int table_id,const struct flow *flow,
		struct flow_wildcards *wc);

unsigned int SGX_cls_rule_priority(struct cls_rule *o_cls_rule);

int SGX_desfet_ccfes_c(void);
void SGX_desfet_ccfes_r(struct cls_rule **buf,int elem);
unsigned int SGX_cls_rule_format(const struct cls_rule *o_cls_rule,struct match *megamatch);
void SGX_miniflow_expand(struct cls_rule *o_cls_rule,struct flow *flow);
uint32_t SGX_rule_calculate_tag(struct cls_rule *o_cls_rule,const struct flow *flow,int table_id);


void SGX_table_dpif_init(int n_tables);
int SGX_table_update_taggable(uint8_t table_id);
int SGX_is_sgx_other_table(int id);
uint32_t SGX_rule_calculate_tag_s(int id,const struct flow *flow,uint32_t secret);
void SGX_oftable_set_name(int table_id, char *name);
uint16_t SGX_minimask_get_vid_mask(struct cls_rule *o_cls_rule);
uint16_t SGX_miniflow_get_vid(struct cls_rule *o_cls_rule);


int SGX_ofproto_get_vlan_usage_c(void);
void SGX_ofproto_get_vlan_usage__r(uint16_t *buf,int elem);




#endif /* !_APP_H_ */
