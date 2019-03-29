#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_start_poller_t {
	int ms_retval;
	async_ecall* ms_data;
} ms_ecall_start_poller_t;

typedef struct ms_ecall_destroy_rule_if_overlaps_t {
	int ms_table_id;
	struct cls_rule* ms_o_cls_rule;
} ms_ecall_destroy_rule_if_overlaps_t;

typedef struct ms_ecall_get_rule_to_evict_if_neccesary_t {
	bool ms_retval;
	int ms_table_id;
	struct cls_rule* ms_o_cls_rule;
} ms_ecall_get_rule_to_evict_if_neccesary_t;

typedef struct ms_ecall_miniflow_expand_and_tag_t {
	uint32_t ms_retval;
	struct cls_rule* ms_o_cls_rule;
	struct flow* ms_flow;
	int ms_table_id;
} ms_ecall_miniflow_expand_and_tag_t;

typedef struct ms_ecall_allocate_cls_rule_if_not_read_only_t {
	bool ms_retval;
	int ms_table_id;
	struct cls_rule* ms_o_cls_rule;
	struct match* ms_match;
	unsigned int ms_priority;
} ms_ecall_allocate_cls_rule_if_not_read_only_t;

typedef struct ms_ecall_classifer_replace_if_modifiable_t {
	int ms_table_id;
	struct cls_rule* ms_o_cls_rule;
	struct cls_rule** ms_cls_rule_rtrn;
	bool* ms_rule_is_modifiable;
} ms_ecall_classifer_replace_if_modifiable_t;

typedef struct ms_ecall_ofproto_init_tables_t {
	int ms_n_tables;
} ms_ecall_ofproto_init_tables_t;

typedef struct ms_ecall_readonly_set_t {
	int ms_table_id;
} ms_ecall_readonly_set_t;

typedef struct ms_ecall_istable_readonly_t {
	int ms_retval;
	uint8_t ms_table_id;
} ms_ecall_istable_readonly_t;

typedef struct ms_ecall_cls_rule_init_t {
	struct cls_rule* ms_o_cls_rule;
	const struct match* ms_match;
	unsigned int ms_priority;
} ms_ecall_cls_rule_init_t;

typedef struct ms_ecall_cr_rule_overlaps_t {
	int ms_retval;
	int ms_table_id;
	struct cls_rule* ms_o_cls_rule;
} ms_ecall_cr_rule_overlaps_t;

typedef struct ms_ecall_cls_rule_destroy_t {
	struct cls_rule* ms_o_cls_rule;
} ms_ecall_cls_rule_destroy_t;

typedef struct ms_ecall_cls_rule_hash_t {
	uint32_t ms_retval;
	const struct cls_rule* ms_o_cls_rule;
	uint32_t ms_basis;
} ms_ecall_cls_rule_hash_t;

typedef struct ms_ecall_cls_rule_equal_t {
	int ms_retval;
	const struct cls_rule* ms_o_cls_rule_a;
	const struct cls_rule* ms_o_cls_rule_b;
} ms_ecall_cls_rule_equal_t;

typedef struct ms_ecall_classifier_replace_t {
	int ms_table_id;
	struct cls_rule* ms_o_cls_rule;
	struct cls_rule** ms_cls_rule_rtrn;
} ms_ecall_classifier_replace_t;

typedef struct ms_ecall_rule_get_flags_t {
	enum oftable_flags ms_retval;
	int ms_table_id;
} ms_ecall_rule_get_flags_t;

typedef struct ms_ecall_cls_count_t {
	int ms_retval;
	int ms_table_id;
} ms_ecall_cls_count_t;

typedef struct ms_ecall_eviction_fields_enable_t {
	int ms_retval;
	int ms_table_id;
} ms_ecall_eviction_fields_enable_t;

typedef struct ms_ecall_evg_group_resize_t {
	int ms_table_id;
	struct cls_rule* ms_o_cls_rule;
	size_t ms_priority;
} ms_ecall_evg_group_resize_t;

typedef struct ms_ecall_evg_add_rule_t {
	size_t ms_retval;
	int ms_table_id;
	struct cls_rule* ms_o_cls_rule;
	uint32_t ms_priority;
	uint32_t ms_rule_evict_prioriy;
	struct heap_node ms_rule_evg_node;
} ms_ecall_evg_add_rule_t;

typedef struct ms_ecall_evg_remove_rule_t {
	int ms_retval;
	int ms_table_id;
	struct cls_rule* ms_o_cls_rule;
} ms_ecall_evg_remove_rule_t;

typedef struct ms_ecall_cls_remove_t {
	int ms_table_id;
	struct cls_rule* ms_o_cls_rule;
} ms_ecall_cls_remove_t;

typedef struct ms_ecall_choose_rule_to_evict_t {
	int ms_table_id;
	struct cls_rule* ms_o_cls_rule;
} ms_ecall_choose_rule_to_evict_t;

typedef struct ms_ecall_table_mflows_t {
	unsigned int ms_retval;
	int ms_table_id;
} ms_ecall_table_mflows_t;

typedef struct ms_ecall_choose_rule_to_evict_p_t {
	int ms_table_id;
	struct cls_rule* ms_o_cls_rule;
} ms_ecall_choose_rule_to_evict_p_t;

typedef struct ms_ecall_minimatch_expand_t {
	struct cls_rule* ms_o_cls_rule;
	struct match* ms_dst;
} ms_ecall_minimatch_expand_t;

typedef struct ms_ecall_cr_priority_t {
	unsigned int ms_retval;
	struct cls_rule* ms_o_cls_rule;
} ms_ecall_cr_priority_t;

typedef struct ms_ecall_cls_find_match_exactly_t {
	int ms_table_id;
	const struct match* ms_target;
	unsigned int ms_priority;
	struct cls_rule** ms_o_cls_rule;
} ms_ecall_cls_find_match_exactly_t;

typedef struct ms_ecall_femt_ccfe_c_t {
	int ms_retval;
	int ms_ofproto_n_tables;
	uint8_t ms_table_id;
	const struct match* ms_match;
} ms_ecall_femt_ccfe_c_t;

typedef struct ms_ecall_femt_ccfe_r_t {
	int ms_ofproto_n_tables;
	struct cls_rule** ms_buf;
	int ms_elem;
	uint8_t ms_table_id;
	const struct match* ms_match;
} ms_ecall_femt_ccfe_r_t;

typedef struct ms_ecall_femt_c_t {
	int ms_retval;
	int ms_ofproto_n_tables;
	uint8_t ms_table_id;
	const struct match* ms_match;
	unsigned int ms_priority;
} ms_ecall_femt_c_t;

typedef struct ms_ecall_femt_r_t {
	int ms_ofproto_n_tables;
	struct cls_rule** ms_buf;
	int ms_elem;
	uint8_t ms_table_id;
	const struct match* ms_match;
	unsigned int ms_priority;
} ms_ecall_femt_r_t;

typedef struct ms_ecall_oftable_enable_eviction_t {
	int ms_table_id;
	const struct mf_subfield* ms_fields;
	size_t ms_n_fields;
	uint32_t ms_random_v;
} ms_ecall_oftable_enable_eviction_t;

typedef struct ms_ecall_oftable_disable_eviction_t {
	int ms_table_id;
} ms_ecall_oftable_disable_eviction_t;

typedef struct ms_ecall_ccfe_c_t {
	int ms_retval;
	int ms_table_id;
} ms_ecall_ccfe_c_t;

typedef struct ms_ecall_ccfe_r_t {
	struct cls_rule** ms_buf;
	int ms_elem;
	int ms_table_id;
} ms_ecall_ccfe_r_t;

typedef struct ms_ecall_table_mflows_set_t {
	int ms_table_id;
	unsigned int ms_value;
} ms_ecall_table_mflows_set_t;

typedef struct ms_ecall_total_rules_t {
	unsigned int ms_retval;
} ms_ecall_total_rules_t;

typedef struct ms_ecall_table_name_t {
	int ms_table_id;
	char* ms_buf;
	size_t ms_len;
} ms_ecall_table_name_t;

typedef struct ms_ecall_collect_ofmonitor_util_c_t {
	int ms_retval;
	int ms_ofproto_n_tables;
	int ms_table_id;
	const struct minimatch* ms_match;
} ms_ecall_collect_ofmonitor_util_c_t;

typedef struct ms_ecall_collect_ofmonitor_util_r_t {
	int ms_ofproto_n_tables;
	struct cls_rule** ms_buf;
	int ms_elem;
	int ms_table_id;
	const struct minimatch* ms_match;
} ms_ecall_collect_ofmonitor_util_r_t;

typedef struct ms_ecall_cls_rule_is_loose_match_t {
	int ms_retval;
	struct cls_rule* ms_o_cls_rule;
	const struct minimatch* ms_criteria;
} ms_ecall_cls_rule_is_loose_match_t;

typedef struct ms_ecall_fet_ccfes_c_t {
	int ms_retval;
} ms_ecall_fet_ccfes_c_t;

typedef struct ms_ecall_fet_ccfes_r_t {
	struct cls_rule** ms_buf;
	int ms_elem;
} ms_ecall_fet_ccfes_r_t;

typedef struct ms_ecall_fet_ccfe_c_t {
	int ms_retval;
} ms_ecall_fet_ccfe_c_t;

typedef struct ms_ecall_fet_ccfe_r_t {
	struct cls_rule** ms_buf;
	int ms_elem;
} ms_ecall_fet_ccfe_r_t;

typedef struct ms_ecall_cls_lookup_t {
	struct cls_rule** ms_o_cls_rule;
	int ms_table_id;
	const struct flow* ms_flow;
	struct flow_wildcards* ms_wc;
} ms_ecall_cls_lookup_t;

typedef struct ms_ecall_cls_rule_priority_t {
	unsigned int ms_retval;
	struct cls_rule* ms_o_cls_rule;
} ms_ecall_cls_rule_priority_t;

typedef struct ms_ecall_desfet_ccfes_c_t {
	int ms_retval;
} ms_ecall_desfet_ccfes_c_t;

typedef struct ms_ecall_desfet_ccfes_r_t {
	struct cls_rule** ms_buf;
	int ms_elem;
} ms_ecall_desfet_ccfes_r_t;

typedef struct ms_ecall_cls_rule_format_t {
	unsigned int ms_retval;
	const struct cls_rule* ms_o_cls_rule;
	struct match* ms_megamatch;
} ms_ecall_cls_rule_format_t;

typedef struct ms_ecall_miniflow_expand_t {
	struct cls_rule* ms_o_cls_rule;
	struct flow* ms_flow;
} ms_ecall_miniflow_expand_t;

typedef struct ms_ecall_rule_calculate_tag_t {
	uint32_t ms_retval;
	struct cls_rule* ms_o_cls_rule;
	const struct flow* ms_flow;
	int ms_table_id;
} ms_ecall_rule_calculate_tag_t;

typedef struct ms_ecall_SGX_table_dpif_t {
	int ms_n_tables;
} ms_ecall_SGX_table_dpif_t;

typedef struct ms_ecall_table_update_taggable_t {
	int ms_retval;
	uint8_t ms_table_id;
} ms_ecall_table_update_taggable_t;

typedef struct ms_ecall_is_sgx_other_table_t {
	int ms_retval;
	int ms_id;
} ms_ecall_is_sgx_other_table_t;

typedef struct ms_ecall_rule_calculate_tag_s_t {
	uint32_t ms_retval;
	int ms_id;
	const struct flow* ms_flow;
	uint32_t ms_secret;
} ms_ecall_rule_calculate_tag_s_t;

typedef struct ms_ecall_oftable_set_name_t {
	int ms_table_id;
	char* ms_name;
} ms_ecall_oftable_set_name_t;

typedef struct ms_ecall_minimask_get_vid_mask_t {
	uint16_t ms_retval;
	struct cls_rule* ms_o_cls_rule;
} ms_ecall_minimask_get_vid_mask_t;

typedef struct ms_ecall_miniflow_get_vid_t {
	uint16_t ms_retval;
	struct cls_rule* ms_o_cls_rule;
} ms_ecall_miniflow_get_vid_t;

typedef struct ms_ecall_ofproto_get_vlan_c_t {
	int ms_retval;
} ms_ecall_ofproto_get_vlan_c_t;

typedef struct ms_ecall_ofproto_get_vlan_r_t {
	uint16_t* ms_buf;
	int ms_elem;
} ms_ecall_ofproto_get_vlan_r_t;

typedef struct ms_ocall_myenclave_sample_t {
	const char* ms_str;
} ms_ocall_myenclave_sample_t;

static sgx_status_t SGX_CDECL enclave_ocall_myenclave_sample(void* pms)
{
	ms_ocall_myenclave_sample_t* ms = SGX_CAST(ms_ocall_myenclave_sample_t*, pms);
	ocall_myenclave_sample(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_sleep(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_sleep();
	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_enclave = {
	2,
	{
		(void*)enclave_ocall_myenclave_sample,
		(void*)enclave_ocall_sleep,
	}
};
sgx_status_t ecall_start_poller(sgx_enclave_id_t eid, int* retval, async_ecall* data)
{
	sgx_status_t status;
	ms_ecall_start_poller_t ms;
	ms.ms_data = data;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_destroy_rule_if_overlaps(sgx_enclave_id_t eid, int table_id, struct cls_rule* o_cls_rule)
{
	sgx_status_t status;
	ms_ecall_destroy_rule_if_overlaps_t ms;
	ms.ms_table_id = table_id;
	ms.ms_o_cls_rule = o_cls_rule;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_get_rule_to_evict_if_neccesary(sgx_enclave_id_t eid, bool* retval, int table_id, struct cls_rule* o_cls_rule)
{
	sgx_status_t status;
	ms_ecall_get_rule_to_evict_if_neccesary_t ms;
	ms.ms_table_id = table_id;
	ms.ms_o_cls_rule = o_cls_rule;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_miniflow_expand_and_tag(sgx_enclave_id_t eid, uint32_t* retval, struct cls_rule* o_cls_rule, struct flow* flow, int table_id)
{
	sgx_status_t status;
	ms_ecall_miniflow_expand_and_tag_t ms;
	ms.ms_o_cls_rule = o_cls_rule;
	ms.ms_flow = flow;
	ms.ms_table_id = table_id;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_allocate_cls_rule_if_not_read_only(sgx_enclave_id_t eid, bool* retval, int table_id, struct cls_rule* o_cls_rule, struct match* match, unsigned int priority)
{
	sgx_status_t status;
	ms_ecall_allocate_cls_rule_if_not_read_only_t ms;
	ms.ms_table_id = table_id;
	ms.ms_o_cls_rule = o_cls_rule;
	ms.ms_match = match;
	ms.ms_priority = priority;
	status = sgx_ecall(eid, 4, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_classifer_replace_if_modifiable(sgx_enclave_id_t eid, int table_id, struct cls_rule* o_cls_rule, struct cls_rule** cls_rule_rtrn, bool* rule_is_modifiable)
{
	sgx_status_t status;
	ms_ecall_classifer_replace_if_modifiable_t ms;
	ms.ms_table_id = table_id;
	ms.ms_o_cls_rule = o_cls_rule;
	ms.ms_cls_rule_rtrn = cls_rule_rtrn;
	ms.ms_rule_is_modifiable = rule_is_modifiable;
	status = sgx_ecall(eid, 5, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_ofproto_init_tables(sgx_enclave_id_t eid, int n_tables)
{
	sgx_status_t status;
	ms_ecall_ofproto_init_tables_t ms;
	ms.ms_n_tables = n_tables;
	status = sgx_ecall(eid, 6, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_readonly_set(sgx_enclave_id_t eid, int table_id)
{
	sgx_status_t status;
	ms_ecall_readonly_set_t ms;
	ms.ms_table_id = table_id;
	status = sgx_ecall(eid, 7, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_istable_readonly(sgx_enclave_id_t eid, int* retval, uint8_t table_id)
{
	sgx_status_t status;
	ms_ecall_istable_readonly_t ms;
	ms.ms_table_id = table_id;
	status = sgx_ecall(eid, 8, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_cls_rule_init(sgx_enclave_id_t eid, struct cls_rule* o_cls_rule, const struct match* match, unsigned int priority)
{
	sgx_status_t status;
	ms_ecall_cls_rule_init_t ms;
	ms.ms_o_cls_rule = o_cls_rule;
	ms.ms_match = match;
	ms.ms_priority = priority;
	status = sgx_ecall(eid, 9, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_cr_rule_overlaps(sgx_enclave_id_t eid, int* retval, int table_id, struct cls_rule* o_cls_rule)
{
	sgx_status_t status;
	ms_ecall_cr_rule_overlaps_t ms;
	ms.ms_table_id = table_id;
	ms.ms_o_cls_rule = o_cls_rule;
	status = sgx_ecall(eid, 10, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_cls_rule_destroy(sgx_enclave_id_t eid, struct cls_rule* o_cls_rule)
{
	sgx_status_t status;
	ms_ecall_cls_rule_destroy_t ms;
	ms.ms_o_cls_rule = o_cls_rule;
	status = sgx_ecall(eid, 11, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_cls_rule_hash(sgx_enclave_id_t eid, uint32_t* retval, const struct cls_rule* o_cls_rule, uint32_t basis)
{
	sgx_status_t status;
	ms_ecall_cls_rule_hash_t ms;
	ms.ms_o_cls_rule = o_cls_rule;
	ms.ms_basis = basis;
	status = sgx_ecall(eid, 12, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_cls_rule_equal(sgx_enclave_id_t eid, int* retval, const struct cls_rule* o_cls_rule_a, const struct cls_rule* o_cls_rule_b)
{
	sgx_status_t status;
	ms_ecall_cls_rule_equal_t ms;
	ms.ms_o_cls_rule_a = o_cls_rule_a;
	ms.ms_o_cls_rule_b = o_cls_rule_b;
	status = sgx_ecall(eid, 13, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_classifier_replace(sgx_enclave_id_t eid, int table_id, struct cls_rule* o_cls_rule, struct cls_rule** cls_rule_rtrn)
{
	sgx_status_t status;
	ms_ecall_classifier_replace_t ms;
	ms.ms_table_id = table_id;
	ms.ms_o_cls_rule = o_cls_rule;
	ms.ms_cls_rule_rtrn = cls_rule_rtrn;
	status = sgx_ecall(eid, 14, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_rule_get_flags(sgx_enclave_id_t eid, enum oftable_flags* retval, int table_id)
{
	sgx_status_t status;
	ms_ecall_rule_get_flags_t ms;
	ms.ms_table_id = table_id;
	status = sgx_ecall(eid, 15, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_cls_count(sgx_enclave_id_t eid, int* retval, int table_id)
{
	sgx_status_t status;
	ms_ecall_cls_count_t ms;
	ms.ms_table_id = table_id;
	status = sgx_ecall(eid, 16, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_eviction_fields_enable(sgx_enclave_id_t eid, int* retval, int table_id)
{
	sgx_status_t status;
	ms_ecall_eviction_fields_enable_t ms;
	ms.ms_table_id = table_id;
	status = sgx_ecall(eid, 17, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_evg_group_resize(sgx_enclave_id_t eid, int table_id, struct cls_rule* o_cls_rule, size_t priority)
{
	sgx_status_t status;
	ms_ecall_evg_group_resize_t ms;
	ms.ms_table_id = table_id;
	ms.ms_o_cls_rule = o_cls_rule;
	ms.ms_priority = priority;
	status = sgx_ecall(eid, 18, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_evg_add_rule(sgx_enclave_id_t eid, size_t* retval, int table_id, struct cls_rule* o_cls_rule, uint32_t priority, uint32_t rule_evict_prioriy, struct heap_node rule_evg_node)
{
	sgx_status_t status;
	ms_ecall_evg_add_rule_t ms;
	ms.ms_table_id = table_id;
	ms.ms_o_cls_rule = o_cls_rule;
	ms.ms_priority = priority;
	ms.ms_rule_evict_prioriy = rule_evict_prioriy;
	ms.ms_rule_evg_node = rule_evg_node;
	status = sgx_ecall(eid, 19, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_evg_remove_rule(sgx_enclave_id_t eid, int* retval, int table_id, struct cls_rule* o_cls_rule)
{
	sgx_status_t status;
	ms_ecall_evg_remove_rule_t ms;
	ms.ms_table_id = table_id;
	ms.ms_o_cls_rule = o_cls_rule;
	status = sgx_ecall(eid, 20, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_cls_remove(sgx_enclave_id_t eid, int table_id, struct cls_rule* o_cls_rule)
{
	sgx_status_t status;
	ms_ecall_cls_remove_t ms;
	ms.ms_table_id = table_id;
	ms.ms_o_cls_rule = o_cls_rule;
	status = sgx_ecall(eid, 21, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_choose_rule_to_evict(sgx_enclave_id_t eid, int table_id, struct cls_rule* o_cls_rule)
{
	sgx_status_t status;
	ms_ecall_choose_rule_to_evict_t ms;
	ms.ms_table_id = table_id;
	ms.ms_o_cls_rule = o_cls_rule;
	status = sgx_ecall(eid, 22, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_table_mflows(sgx_enclave_id_t eid, unsigned int* retval, int table_id)
{
	sgx_status_t status;
	ms_ecall_table_mflows_t ms;
	ms.ms_table_id = table_id;
	status = sgx_ecall(eid, 23, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_choose_rule_to_evict_p(sgx_enclave_id_t eid, int table_id, struct cls_rule* o_cls_rule)
{
	sgx_status_t status;
	ms_ecall_choose_rule_to_evict_p_t ms;
	ms.ms_table_id = table_id;
	ms.ms_o_cls_rule = o_cls_rule;
	status = sgx_ecall(eid, 24, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_minimatch_expand(sgx_enclave_id_t eid, struct cls_rule* o_cls_rule, struct match* dst)
{
	sgx_status_t status;
	ms_ecall_minimatch_expand_t ms;
	ms.ms_o_cls_rule = o_cls_rule;
	ms.ms_dst = dst;
	status = sgx_ecall(eid, 25, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_cr_priority(sgx_enclave_id_t eid, unsigned int* retval, struct cls_rule* o_cls_rule)
{
	sgx_status_t status;
	ms_ecall_cr_priority_t ms;
	ms.ms_o_cls_rule = o_cls_rule;
	status = sgx_ecall(eid, 26, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_cls_find_match_exactly(sgx_enclave_id_t eid, int table_id, const struct match* target, unsigned int priority, struct cls_rule** o_cls_rule)
{
	sgx_status_t status;
	ms_ecall_cls_find_match_exactly_t ms;
	ms.ms_table_id = table_id;
	ms.ms_target = target;
	ms.ms_priority = priority;
	ms.ms_o_cls_rule = o_cls_rule;
	status = sgx_ecall(eid, 27, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_femt_ccfe_c(sgx_enclave_id_t eid, int* retval, int ofproto_n_tables, uint8_t table_id, const struct match* match)
{
	sgx_status_t status;
	ms_ecall_femt_ccfe_c_t ms;
	ms.ms_ofproto_n_tables = ofproto_n_tables;
	ms.ms_table_id = table_id;
	ms.ms_match = match;
	status = sgx_ecall(eid, 28, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_femt_ccfe_r(sgx_enclave_id_t eid, int ofproto_n_tables, struct cls_rule** buf, int elem, uint8_t table_id, const struct match* match)
{
	sgx_status_t status;
	ms_ecall_femt_ccfe_r_t ms;
	ms.ms_ofproto_n_tables = ofproto_n_tables;
	ms.ms_buf = buf;
	ms.ms_elem = elem;
	ms.ms_table_id = table_id;
	ms.ms_match = match;
	status = sgx_ecall(eid, 29, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_femt_c(sgx_enclave_id_t eid, int* retval, int ofproto_n_tables, uint8_t table_id, const struct match* match, unsigned int priority)
{
	sgx_status_t status;
	ms_ecall_femt_c_t ms;
	ms.ms_ofproto_n_tables = ofproto_n_tables;
	ms.ms_table_id = table_id;
	ms.ms_match = match;
	ms.ms_priority = priority;
	status = sgx_ecall(eid, 30, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_femt_r(sgx_enclave_id_t eid, int ofproto_n_tables, struct cls_rule** buf, int elem, uint8_t table_id, const struct match* match, unsigned int priority)
{
	sgx_status_t status;
	ms_ecall_femt_r_t ms;
	ms.ms_ofproto_n_tables = ofproto_n_tables;
	ms.ms_buf = buf;
	ms.ms_elem = elem;
	ms.ms_table_id = table_id;
	ms.ms_match = match;
	ms.ms_priority = priority;
	status = sgx_ecall(eid, 31, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_oftable_enable_eviction(sgx_enclave_id_t eid, int table_id, const struct mf_subfield* fields, size_t n_fields, uint32_t random_v)
{
	sgx_status_t status;
	ms_ecall_oftable_enable_eviction_t ms;
	ms.ms_table_id = table_id;
	ms.ms_fields = fields;
	ms.ms_n_fields = n_fields;
	ms.ms_random_v = random_v;
	status = sgx_ecall(eid, 32, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_oftable_disable_eviction(sgx_enclave_id_t eid, int table_id)
{
	sgx_status_t status;
	ms_ecall_oftable_disable_eviction_t ms;
	ms.ms_table_id = table_id;
	status = sgx_ecall(eid, 33, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_ccfe_c(sgx_enclave_id_t eid, int* retval, int table_id)
{
	sgx_status_t status;
	ms_ecall_ccfe_c_t ms;
	ms.ms_table_id = table_id;
	status = sgx_ecall(eid, 34, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_ccfe_r(sgx_enclave_id_t eid, struct cls_rule** buf, int elem, int table_id)
{
	sgx_status_t status;
	ms_ecall_ccfe_r_t ms;
	ms.ms_buf = buf;
	ms.ms_elem = elem;
	ms.ms_table_id = table_id;
	status = sgx_ecall(eid, 35, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_table_mflows_set(sgx_enclave_id_t eid, int table_id, unsigned int value)
{
	sgx_status_t status;
	ms_ecall_table_mflows_set_t ms;
	ms.ms_table_id = table_id;
	ms.ms_value = value;
	status = sgx_ecall(eid, 36, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_ofproto_destroy(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 37, &ocall_table_enclave, NULL);
	return status;
}

sgx_status_t ecall_total_rules(sgx_enclave_id_t eid, unsigned int* retval)
{
	sgx_status_t status;
	ms_ecall_total_rules_t ms;
	status = sgx_ecall(eid, 38, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_table_name(sgx_enclave_id_t eid, int table_id, char* buf, size_t len)
{
	sgx_status_t status;
	ms_ecall_table_name_t ms;
	ms.ms_table_id = table_id;
	ms.ms_buf = buf;
	ms.ms_len = len;
	status = sgx_ecall(eid, 39, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_collect_ofmonitor_util_c(sgx_enclave_id_t eid, int* retval, int ofproto_n_tables, int table_id, const struct minimatch* match)
{
	sgx_status_t status;
	ms_ecall_collect_ofmonitor_util_c_t ms;
	ms.ms_ofproto_n_tables = ofproto_n_tables;
	ms.ms_table_id = table_id;
	ms.ms_match = match;
	status = sgx_ecall(eid, 40, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_collect_ofmonitor_util_r(sgx_enclave_id_t eid, int ofproto_n_tables, struct cls_rule** buf, int elem, int table_id, const struct minimatch* match)
{
	sgx_status_t status;
	ms_ecall_collect_ofmonitor_util_r_t ms;
	ms.ms_ofproto_n_tables = ofproto_n_tables;
	ms.ms_buf = buf;
	ms.ms_elem = elem;
	ms.ms_table_id = table_id;
	ms.ms_match = match;
	status = sgx_ecall(eid, 41, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_cls_rule_is_loose_match(sgx_enclave_id_t eid, int* retval, struct cls_rule* o_cls_rule, const struct minimatch* criteria)
{
	sgx_status_t status;
	ms_ecall_cls_rule_is_loose_match_t ms;
	ms.ms_o_cls_rule = o_cls_rule;
	ms.ms_criteria = criteria;
	status = sgx_ecall(eid, 42, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_fet_ccfes_c(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_fet_ccfes_c_t ms;
	status = sgx_ecall(eid, 43, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_fet_ccfes_r(sgx_enclave_id_t eid, struct cls_rule** buf, int elem)
{
	sgx_status_t status;
	ms_ecall_fet_ccfes_r_t ms;
	ms.ms_buf = buf;
	ms.ms_elem = elem;
	status = sgx_ecall(eid, 44, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_fet_ccfe_c(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_fet_ccfe_c_t ms;
	status = sgx_ecall(eid, 45, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_fet_ccfe_r(sgx_enclave_id_t eid, struct cls_rule** buf, int elem)
{
	sgx_status_t status;
	ms_ecall_fet_ccfe_r_t ms;
	ms.ms_buf = buf;
	ms.ms_elem = elem;
	status = sgx_ecall(eid, 46, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_cls_lookup(sgx_enclave_id_t eid, struct cls_rule** o_cls_rule, int table_id, const struct flow* flow, struct flow_wildcards* wc)
{
	sgx_status_t status;
	ms_ecall_cls_lookup_t ms;
	ms.ms_o_cls_rule = o_cls_rule;
	ms.ms_table_id = table_id;
	ms.ms_flow = flow;
	ms.ms_wc = wc;
	status = sgx_ecall(eid, 47, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_cls_rule_priority(sgx_enclave_id_t eid, unsigned int* retval, struct cls_rule* o_cls_rule)
{
	sgx_status_t status;
	ms_ecall_cls_rule_priority_t ms;
	ms.ms_o_cls_rule = o_cls_rule;
	status = sgx_ecall(eid, 48, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_desfet_ccfes_c(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_desfet_ccfes_c_t ms;
	status = sgx_ecall(eid, 49, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_desfet_ccfes_r(sgx_enclave_id_t eid, struct cls_rule** buf, int elem)
{
	sgx_status_t status;
	ms_ecall_desfet_ccfes_r_t ms;
	ms.ms_buf = buf;
	ms.ms_elem = elem;
	status = sgx_ecall(eid, 50, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_cls_rule_format(sgx_enclave_id_t eid, unsigned int* retval, const struct cls_rule* o_cls_rule, struct match* megamatch)
{
	sgx_status_t status;
	ms_ecall_cls_rule_format_t ms;
	ms.ms_o_cls_rule = o_cls_rule;
	ms.ms_megamatch = megamatch;
	status = sgx_ecall(eid, 51, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_miniflow_expand(sgx_enclave_id_t eid, struct cls_rule* o_cls_rule, struct flow* flow)
{
	sgx_status_t status;
	ms_ecall_miniflow_expand_t ms;
	ms.ms_o_cls_rule = o_cls_rule;
	ms.ms_flow = flow;
	status = sgx_ecall(eid, 52, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_rule_calculate_tag(sgx_enclave_id_t eid, uint32_t* retval, struct cls_rule* o_cls_rule, const struct flow* flow, int table_id)
{
	sgx_status_t status;
	ms_ecall_rule_calculate_tag_t ms;
	ms.ms_o_cls_rule = o_cls_rule;
	ms.ms_flow = flow;
	ms.ms_table_id = table_id;
	status = sgx_ecall(eid, 53, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_SGX_table_dpif(sgx_enclave_id_t eid, int n_tables)
{
	sgx_status_t status;
	ms_ecall_SGX_table_dpif_t ms;
	ms.ms_n_tables = n_tables;
	status = sgx_ecall(eid, 54, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_table_update_taggable(sgx_enclave_id_t eid, int* retval, uint8_t table_id)
{
	sgx_status_t status;
	ms_ecall_table_update_taggable_t ms;
	ms.ms_table_id = table_id;
	status = sgx_ecall(eid, 55, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_is_sgx_other_table(sgx_enclave_id_t eid, int* retval, int id)
{
	sgx_status_t status;
	ms_ecall_is_sgx_other_table_t ms;
	ms.ms_id = id;
	status = sgx_ecall(eid, 56, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_rule_calculate_tag_s(sgx_enclave_id_t eid, uint32_t* retval, int id, const struct flow* flow, uint32_t secret)
{
	sgx_status_t status;
	ms_ecall_rule_calculate_tag_s_t ms;
	ms.ms_id = id;
	ms.ms_flow = flow;
	ms.ms_secret = secret;
	status = sgx_ecall(eid, 57, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_hidden_tables_check(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 58, &ocall_table_enclave, NULL);
	return status;
}

sgx_status_t ecall_oftable_set_name(sgx_enclave_id_t eid, int table_id, char* name)
{
	sgx_status_t status;
	ms_ecall_oftable_set_name_t ms;
	ms.ms_table_id = table_id;
	ms.ms_name = name;
	status = sgx_ecall(eid, 59, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_minimask_get_vid_mask(sgx_enclave_id_t eid, uint16_t* retval, struct cls_rule* o_cls_rule)
{
	sgx_status_t status;
	ms_ecall_minimask_get_vid_mask_t ms;
	ms.ms_o_cls_rule = o_cls_rule;
	status = sgx_ecall(eid, 60, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_miniflow_get_vid(sgx_enclave_id_t eid, uint16_t* retval, struct cls_rule* o_cls_rule)
{
	sgx_status_t status;
	ms_ecall_miniflow_get_vid_t ms;
	ms.ms_o_cls_rule = o_cls_rule;
	status = sgx_ecall(eid, 61, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_ofproto_get_vlan_c(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_ofproto_get_vlan_c_t ms;
	status = sgx_ecall(eid, 62, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_ofproto_get_vlan_r(sgx_enclave_id_t eid, uint16_t* buf, int elem)
{
	sgx_status_t status;
	ms_ecall_ofproto_get_vlan_r_t ms;
	ms.ms_buf = buf;
	ms.ms_elem = elem;
	status = sgx_ecall(eid, 63, &ocall_table_enclave, &ms);
	return status;
}

