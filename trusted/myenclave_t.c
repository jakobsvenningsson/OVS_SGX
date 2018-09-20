#include "myenclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_ecall_myenclave_sample_t {
	int ms_retval;
} ms_ecall_myenclave_sample_t;

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
	struct match* ms_match;
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
	struct cls_rule* ms_o_cls_rule;
	uint32_t ms_basis;
} ms_ecall_cls_rule_hash_t;

typedef struct ms_ecall_cls_rule_equal_t {
	int ms_retval;
	struct cls_rule* ms_o_cls_rule_a;
	struct cls_rule* ms_o_cls_rule_b;
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
	struct match* ms_target;
	unsigned int ms_priority;
	struct cls_rule** ms_o_cls_rule;
} ms_ecall_cls_find_match_exactly_t;

typedef struct ms_ecall_femt_ccfe_c_t {
	int ms_retval;
	int ms_ofproto_n_tables;
	uint8_t ms_table_id;
	struct match* ms_match;
} ms_ecall_femt_ccfe_c_t;

typedef struct ms_ecall_femt_ccfe_r_t {
	int ms_ofproto_n_tables;
	struct cls_rule** ms_buf;
	int ms_elem;
	uint8_t ms_table_id;
	struct match* ms_match;
} ms_ecall_femt_ccfe_r_t;

typedef struct ms_ecall_femt_c_t {
	int ms_retval;
	int ms_ofproto_n_tables;
	uint8_t ms_table_id;
	struct match* ms_match;
	unsigned int ms_priority;
} ms_ecall_femt_c_t;

typedef struct ms_ecall_femt_r_t {
	int ms_ofproto_n_tables;
	struct cls_rule** ms_buf;
	int ms_elem;
	uint8_t ms_table_id;
	struct match* ms_match;
	unsigned int ms_priority;
} ms_ecall_femt_r_t;

typedef struct ms_ecall_oftable_enable_eviction_t {
	int ms_table_id;
	struct mf_subfield* ms_fields;
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
	struct minimatch* ms_match;
} ms_ecall_collect_ofmonitor_util_c_t;

typedef struct ms_ecall_collect_ofmonitor_util_r_t {
	int ms_ofproto_n_tables;
	struct cls_rule** ms_buf;
	int ms_elem;
	int ms_table_id;
	struct minimatch* ms_match;
} ms_ecall_collect_ofmonitor_util_r_t;

typedef struct ms_ecall_cls_rule_is_loose_match_t {
	int ms_retval;
	struct cls_rule* ms_o_cls_rule;
	struct minimatch* ms_criteria;
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
	struct flow* ms_flow;
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
	struct cls_rule* ms_o_cls_rule;
	struct match* ms_megamatch;
} ms_ecall_cls_rule_format_t;

typedef struct ms_ecall_miniflow_expand_t {
	struct cls_rule* ms_o_cls_rule;
	struct flow* ms_flow;
} ms_ecall_miniflow_expand_t;

typedef struct ms_ecall_rule_calculate_tag_t {
	uint32_t ms_retval;
	struct cls_rule* ms_o_cls_rule;
	struct flow* ms_flow;
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
	struct flow* ms_flow;
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
	char* ms_str;
} ms_ocall_myenclave_sample_t;

static sgx_status_t SGX_CDECL sgx_ecall_myenclave_sample(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_myenclave_sample_t));
	ms_ecall_myenclave_sample_t* ms = SGX_CAST(ms_ecall_myenclave_sample_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_myenclave_sample();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_ofproto_init_tables(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_ofproto_init_tables_t));
	ms_ecall_ofproto_init_tables_t* ms = SGX_CAST(ms_ecall_ofproto_init_tables_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_ofproto_init_tables(ms->ms_n_tables);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_readonly_set(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_readonly_set_t));
	ms_ecall_readonly_set_t* ms = SGX_CAST(ms_ecall_readonly_set_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_readonly_set(ms->ms_table_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_istable_readonly(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_istable_readonly_t));
	ms_ecall_istable_readonly_t* ms = SGX_CAST(ms_ecall_istable_readonly_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_istable_readonly(ms->ms_table_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_cls_rule_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_cls_rule_init_t));
	ms_ecall_cls_rule_init_t* ms = SGX_CAST(ms_ecall_cls_rule_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;
	struct match* _tmp_match = ms->ms_match;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_cls_rule_init(_tmp_o_cls_rule, (const struct match*)_tmp_match, ms->ms_priority);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_cr_rule_overlaps(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_cr_rule_overlaps_t));
	ms_ecall_cr_rule_overlaps_t* ms = SGX_CAST(ms_ecall_cr_rule_overlaps_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_cr_rule_overlaps(ms->ms_table_id, _tmp_o_cls_rule);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_cls_rule_destroy(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_cls_rule_destroy_t));
	ms_ecall_cls_rule_destroy_t* ms = SGX_CAST(ms_ecall_cls_rule_destroy_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_cls_rule_destroy(_tmp_o_cls_rule);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_cls_rule_hash(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_cls_rule_hash_t));
	ms_ecall_cls_rule_hash_t* ms = SGX_CAST(ms_ecall_cls_rule_hash_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_cls_rule_hash((const struct cls_rule*)_tmp_o_cls_rule, ms->ms_basis);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_cls_rule_equal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_cls_rule_equal_t));
	ms_ecall_cls_rule_equal_t* ms = SGX_CAST(ms_ecall_cls_rule_equal_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule_a = ms->ms_o_cls_rule_a;
	struct cls_rule* _tmp_o_cls_rule_b = ms->ms_o_cls_rule_b;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_cls_rule_equal((const struct cls_rule*)_tmp_o_cls_rule_a, (const struct cls_rule*)_tmp_o_cls_rule_b);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_classifier_replace(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_classifier_replace_t));
	ms_ecall_classifier_replace_t* ms = SGX_CAST(ms_ecall_classifier_replace_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;
	struct cls_rule** _tmp_cls_rule_rtrn = ms->ms_cls_rule_rtrn;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_classifier_replace(ms->ms_table_id, _tmp_o_cls_rule, _tmp_cls_rule_rtrn);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_rule_get_flags(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_rule_get_flags_t));
	ms_ecall_rule_get_flags_t* ms = SGX_CAST(ms_ecall_rule_get_flags_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_rule_get_flags(ms->ms_table_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_cls_count(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_cls_count_t));
	ms_ecall_cls_count_t* ms = SGX_CAST(ms_ecall_cls_count_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_cls_count(ms->ms_table_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_eviction_fields_enable(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_eviction_fields_enable_t));
	ms_ecall_eviction_fields_enable_t* ms = SGX_CAST(ms_ecall_eviction_fields_enable_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_eviction_fields_enable(ms->ms_table_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_evg_group_resize(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_evg_group_resize_t));
	ms_ecall_evg_group_resize_t* ms = SGX_CAST(ms_ecall_evg_group_resize_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_evg_group_resize(ms->ms_table_id, _tmp_o_cls_rule, ms->ms_priority);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_evg_add_rule(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_evg_add_rule_t));
	ms_ecall_evg_add_rule_t* ms = SGX_CAST(ms_ecall_evg_add_rule_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_evg_add_rule(ms->ms_table_id, _tmp_o_cls_rule, ms->ms_priority, ms->ms_rule_evict_prioriy, ms->ms_rule_evg_node);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_evg_remove_rule(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_evg_remove_rule_t));
	ms_ecall_evg_remove_rule_t* ms = SGX_CAST(ms_ecall_evg_remove_rule_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_evg_remove_rule(ms->ms_table_id, _tmp_o_cls_rule);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_cls_remove(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_cls_remove_t));
	ms_ecall_cls_remove_t* ms = SGX_CAST(ms_ecall_cls_remove_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_cls_remove(ms->ms_table_id, _tmp_o_cls_rule);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_choose_rule_to_evict(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_choose_rule_to_evict_t));
	ms_ecall_choose_rule_to_evict_t* ms = SGX_CAST(ms_ecall_choose_rule_to_evict_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_choose_rule_to_evict(ms->ms_table_id, _tmp_o_cls_rule);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_table_mflows(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_table_mflows_t));
	ms_ecall_table_mflows_t* ms = SGX_CAST(ms_ecall_table_mflows_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_table_mflows(ms->ms_table_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_choose_rule_to_evict_p(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_choose_rule_to_evict_p_t));
	ms_ecall_choose_rule_to_evict_p_t* ms = SGX_CAST(ms_ecall_choose_rule_to_evict_p_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_choose_rule_to_evict_p(ms->ms_table_id, _tmp_o_cls_rule);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_minimatch_expand(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_minimatch_expand_t));
	ms_ecall_minimatch_expand_t* ms = SGX_CAST(ms_ecall_minimatch_expand_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;
	struct match* _tmp_dst = ms->ms_dst;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_minimatch_expand(_tmp_o_cls_rule, _tmp_dst);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_cr_priority(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_cr_priority_t));
	ms_ecall_cr_priority_t* ms = SGX_CAST(ms_ecall_cr_priority_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_cr_priority(_tmp_o_cls_rule);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_cls_find_match_exactly(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_cls_find_match_exactly_t));
	ms_ecall_cls_find_match_exactly_t* ms = SGX_CAST(ms_ecall_cls_find_match_exactly_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct match* _tmp_target = ms->ms_target;
	struct cls_rule** _tmp_o_cls_rule = ms->ms_o_cls_rule;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_cls_find_match_exactly(ms->ms_table_id, (const struct match*)_tmp_target, ms->ms_priority, _tmp_o_cls_rule);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_femt_ccfe_c(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_femt_ccfe_c_t));
	ms_ecall_femt_ccfe_c_t* ms = SGX_CAST(ms_ecall_femt_ccfe_c_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct match* _tmp_match = ms->ms_match;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_femt_ccfe_c(ms->ms_ofproto_n_tables, ms->ms_table_id, (const struct match*)_tmp_match);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_femt_ccfe_r(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_femt_ccfe_r_t));
	ms_ecall_femt_ccfe_r_t* ms = SGX_CAST(ms_ecall_femt_ccfe_r_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule** _tmp_buf = ms->ms_buf;
	struct match* _tmp_match = ms->ms_match;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_femt_ccfe_r(ms->ms_ofproto_n_tables, _tmp_buf, ms->ms_elem, ms->ms_table_id, (const struct match*)_tmp_match);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_femt_c(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_femt_c_t));
	ms_ecall_femt_c_t* ms = SGX_CAST(ms_ecall_femt_c_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct match* _tmp_match = ms->ms_match;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_femt_c(ms->ms_ofproto_n_tables, ms->ms_table_id, (const struct match*)_tmp_match, ms->ms_priority);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_femt_r(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_femt_r_t));
	ms_ecall_femt_r_t* ms = SGX_CAST(ms_ecall_femt_r_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule** _tmp_buf = ms->ms_buf;
	struct match* _tmp_match = ms->ms_match;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_femt_r(ms->ms_ofproto_n_tables, _tmp_buf, ms->ms_elem, ms->ms_table_id, (const struct match*)_tmp_match, ms->ms_priority);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_oftable_enable_eviction(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_oftable_enable_eviction_t));
	ms_ecall_oftable_enable_eviction_t* ms = SGX_CAST(ms_ecall_oftable_enable_eviction_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct mf_subfield* _tmp_fields = ms->ms_fields;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_oftable_enable_eviction(ms->ms_table_id, (const struct mf_subfield*)_tmp_fields, ms->ms_n_fields, ms->ms_random_v);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_oftable_disable_eviction(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_oftable_disable_eviction_t));
	ms_ecall_oftable_disable_eviction_t* ms = SGX_CAST(ms_ecall_oftable_disable_eviction_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_oftable_disable_eviction(ms->ms_table_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_ccfe_c(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_ccfe_c_t));
	ms_ecall_ccfe_c_t* ms = SGX_CAST(ms_ecall_ccfe_c_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_ccfe_c(ms->ms_table_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_ccfe_r(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_ccfe_r_t));
	ms_ecall_ccfe_r_t* ms = SGX_CAST(ms_ecall_ccfe_r_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule** _tmp_buf = ms->ms_buf;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_ccfe_r(_tmp_buf, ms->ms_elem, ms->ms_table_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_table_mflows_set(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_table_mflows_set_t));
	ms_ecall_table_mflows_set_t* ms = SGX_CAST(ms_ecall_table_mflows_set_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_table_mflows_set(ms->ms_table_id, ms->ms_value);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_ofproto_destroy(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_ofproto_destroy();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_total_rules(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_total_rules_t));
	ms_ecall_total_rules_t* ms = SGX_CAST(ms_ecall_total_rules_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_total_rules();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_table_name(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_table_name_t));
	ms_ecall_table_name_t* ms = SGX_CAST(ms_ecall_table_name_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buf = ms->ms_buf;
	size_t _tmp_len = ms->ms_len;
	size_t _len_buf = _tmp_len;
	char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);


	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ((_in_buf = (char*)malloc(_len_buf)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_buf, 0, _len_buf);
	}

	ecall_table_name(ms->ms_table_id, _in_buf, _tmp_len);
err:
	if (_in_buf) {
		memcpy(_tmp_buf, _in_buf, _len_buf);
		free(_in_buf);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_collect_ofmonitor_util_c(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_collect_ofmonitor_util_c_t));
	ms_ecall_collect_ofmonitor_util_c_t* ms = SGX_CAST(ms_ecall_collect_ofmonitor_util_c_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct minimatch* _tmp_match = ms->ms_match;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_collect_ofmonitor_util_c(ms->ms_ofproto_n_tables, ms->ms_table_id, (const struct minimatch*)_tmp_match);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_collect_ofmonitor_util_r(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_collect_ofmonitor_util_r_t));
	ms_ecall_collect_ofmonitor_util_r_t* ms = SGX_CAST(ms_ecall_collect_ofmonitor_util_r_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule** _tmp_buf = ms->ms_buf;
	struct minimatch* _tmp_match = ms->ms_match;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_collect_ofmonitor_util_r(ms->ms_ofproto_n_tables, _tmp_buf, ms->ms_elem, ms->ms_table_id, (const struct minimatch*)_tmp_match);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_cls_rule_is_loose_match(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_cls_rule_is_loose_match_t));
	ms_ecall_cls_rule_is_loose_match_t* ms = SGX_CAST(ms_ecall_cls_rule_is_loose_match_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;
	struct minimatch* _tmp_criteria = ms->ms_criteria;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_cls_rule_is_loose_match(_tmp_o_cls_rule, (const struct minimatch*)_tmp_criteria);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_fet_ccfes_c(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_fet_ccfes_c_t));
	ms_ecall_fet_ccfes_c_t* ms = SGX_CAST(ms_ecall_fet_ccfes_c_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_fet_ccfes_c();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_fet_ccfes_r(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_fet_ccfes_r_t));
	ms_ecall_fet_ccfes_r_t* ms = SGX_CAST(ms_ecall_fet_ccfes_r_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule** _tmp_buf = ms->ms_buf;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_fet_ccfes_r(_tmp_buf, ms->ms_elem);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_fet_ccfe_c(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_fet_ccfe_c_t));
	ms_ecall_fet_ccfe_c_t* ms = SGX_CAST(ms_ecall_fet_ccfe_c_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_fet_ccfe_c();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_fet_ccfe_r(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_fet_ccfe_r_t));
	ms_ecall_fet_ccfe_r_t* ms = SGX_CAST(ms_ecall_fet_ccfe_r_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule** _tmp_buf = ms->ms_buf;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_fet_ccfe_r(_tmp_buf, ms->ms_elem);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_cls_lookup(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_cls_lookup_t));
	ms_ecall_cls_lookup_t* ms = SGX_CAST(ms_ecall_cls_lookup_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule** _tmp_o_cls_rule = ms->ms_o_cls_rule;
	struct flow* _tmp_flow = ms->ms_flow;
	struct flow_wildcards* _tmp_wc = ms->ms_wc;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_cls_lookup(_tmp_o_cls_rule, ms->ms_table_id, (const struct flow*)_tmp_flow, _tmp_wc);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_cls_rule_priority(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_cls_rule_priority_t));
	ms_ecall_cls_rule_priority_t* ms = SGX_CAST(ms_ecall_cls_rule_priority_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_cls_rule_priority(_tmp_o_cls_rule);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_desfet_ccfes_c(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_desfet_ccfes_c_t));
	ms_ecall_desfet_ccfes_c_t* ms = SGX_CAST(ms_ecall_desfet_ccfes_c_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_desfet_ccfes_c();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_desfet_ccfes_r(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_desfet_ccfes_r_t));
	ms_ecall_desfet_ccfes_r_t* ms = SGX_CAST(ms_ecall_desfet_ccfes_r_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule** _tmp_buf = ms->ms_buf;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_desfet_ccfes_r(_tmp_buf, ms->ms_elem);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_cls_rule_format(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_cls_rule_format_t));
	ms_ecall_cls_rule_format_t* ms = SGX_CAST(ms_ecall_cls_rule_format_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;
	struct match* _tmp_megamatch = ms->ms_megamatch;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_cls_rule_format((const struct cls_rule*)_tmp_o_cls_rule, _tmp_megamatch);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_miniflow_expand(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_miniflow_expand_t));
	ms_ecall_miniflow_expand_t* ms = SGX_CAST(ms_ecall_miniflow_expand_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;
	struct flow* _tmp_flow = ms->ms_flow;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_miniflow_expand(_tmp_o_cls_rule, _tmp_flow);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_rule_calculate_tag(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_rule_calculate_tag_t));
	ms_ecall_rule_calculate_tag_t* ms = SGX_CAST(ms_ecall_rule_calculate_tag_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;
	struct flow* _tmp_flow = ms->ms_flow;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_rule_calculate_tag(_tmp_o_cls_rule, (const struct flow*)_tmp_flow, ms->ms_table_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_SGX_table_dpif(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_SGX_table_dpif_t));
	ms_ecall_SGX_table_dpif_t* ms = SGX_CAST(ms_ecall_SGX_table_dpif_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_SGX_table_dpif(ms->ms_n_tables);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_table_update_taggable(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_table_update_taggable_t));
	ms_ecall_table_update_taggable_t* ms = SGX_CAST(ms_ecall_table_update_taggable_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_table_update_taggable(ms->ms_table_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_is_sgx_other_table(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_is_sgx_other_table_t));
	ms_ecall_is_sgx_other_table_t* ms = SGX_CAST(ms_ecall_is_sgx_other_table_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_is_sgx_other_table(ms->ms_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_rule_calculate_tag_s(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_rule_calculate_tag_s_t));
	ms_ecall_rule_calculate_tag_s_t* ms = SGX_CAST(ms_ecall_rule_calculate_tag_s_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct flow* _tmp_flow = ms->ms_flow;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_rule_calculate_tag_s(ms->ms_id, (const struct flow*)_tmp_flow, ms->ms_secret);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_hidden_tables_check(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_hidden_tables_check();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_oftable_set_name(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_oftable_set_name_t));
	ms_ecall_oftable_set_name_t* ms = SGX_CAST(ms_ecall_oftable_set_name_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_name = ms->ms_name;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_oftable_set_name(ms->ms_table_id, _tmp_name);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_minimask_get_vid_mask(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_minimask_get_vid_mask_t));
	ms_ecall_minimask_get_vid_mask_t* ms = SGX_CAST(ms_ecall_minimask_get_vid_mask_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_minimask_get_vid_mask(_tmp_o_cls_rule);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_miniflow_get_vid(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_miniflow_get_vid_t));
	ms_ecall_miniflow_get_vid_t* ms = SGX_CAST(ms_ecall_miniflow_get_vid_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct cls_rule* _tmp_o_cls_rule = ms->ms_o_cls_rule;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_miniflow_get_vid(_tmp_o_cls_rule);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_ofproto_get_vlan_c(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_ofproto_get_vlan_c_t));
	ms_ecall_ofproto_get_vlan_c_t* ms = SGX_CAST(ms_ecall_ofproto_get_vlan_c_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ms->ms_retval = ecall_ofproto_get_vlan_c();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_ofproto_get_vlan_r(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_ofproto_get_vlan_r_t));
	ms_ecall_ofproto_get_vlan_r_t* ms = SGX_CAST(ms_ecall_ofproto_get_vlan_r_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint16_t* _tmp_buf = ms->ms_buf;



	//
	// fence after pointer checks
	//
	__builtin_ia32_lfence();


	ecall_ofproto_get_vlan_r(_tmp_buf, ms->ms_elem);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[59];
} g_ecall_table = {
	59,
	{
		{(void*)(uintptr_t)sgx_ecall_myenclave_sample, 0},
		{(void*)(uintptr_t)sgx_ecall_ofproto_init_tables, 0},
		{(void*)(uintptr_t)sgx_ecall_readonly_set, 0},
		{(void*)(uintptr_t)sgx_ecall_istable_readonly, 0},
		{(void*)(uintptr_t)sgx_ecall_cls_rule_init, 0},
		{(void*)(uintptr_t)sgx_ecall_cr_rule_overlaps, 0},
		{(void*)(uintptr_t)sgx_ecall_cls_rule_destroy, 0},
		{(void*)(uintptr_t)sgx_ecall_cls_rule_hash, 0},
		{(void*)(uintptr_t)sgx_ecall_cls_rule_equal, 0},
		{(void*)(uintptr_t)sgx_ecall_classifier_replace, 0},
		{(void*)(uintptr_t)sgx_ecall_rule_get_flags, 0},
		{(void*)(uintptr_t)sgx_ecall_cls_count, 0},
		{(void*)(uintptr_t)sgx_ecall_eviction_fields_enable, 0},
		{(void*)(uintptr_t)sgx_ecall_evg_group_resize, 0},
		{(void*)(uintptr_t)sgx_ecall_evg_add_rule, 0},
		{(void*)(uintptr_t)sgx_ecall_evg_remove_rule, 0},
		{(void*)(uintptr_t)sgx_ecall_cls_remove, 0},
		{(void*)(uintptr_t)sgx_ecall_choose_rule_to_evict, 0},
		{(void*)(uintptr_t)sgx_ecall_table_mflows, 0},
		{(void*)(uintptr_t)sgx_ecall_choose_rule_to_evict_p, 0},
		{(void*)(uintptr_t)sgx_ecall_minimatch_expand, 0},
		{(void*)(uintptr_t)sgx_ecall_cr_priority, 0},
		{(void*)(uintptr_t)sgx_ecall_cls_find_match_exactly, 0},
		{(void*)(uintptr_t)sgx_ecall_femt_ccfe_c, 0},
		{(void*)(uintptr_t)sgx_ecall_femt_ccfe_r, 0},
		{(void*)(uintptr_t)sgx_ecall_femt_c, 0},
		{(void*)(uintptr_t)sgx_ecall_femt_r, 0},
		{(void*)(uintptr_t)sgx_ecall_oftable_enable_eviction, 0},
		{(void*)(uintptr_t)sgx_ecall_oftable_disable_eviction, 0},
		{(void*)(uintptr_t)sgx_ecall_ccfe_c, 0},
		{(void*)(uintptr_t)sgx_ecall_ccfe_r, 0},
		{(void*)(uintptr_t)sgx_ecall_table_mflows_set, 0},
		{(void*)(uintptr_t)sgx_ecall_ofproto_destroy, 0},
		{(void*)(uintptr_t)sgx_ecall_total_rules, 0},
		{(void*)(uintptr_t)sgx_ecall_table_name, 0},
		{(void*)(uintptr_t)sgx_ecall_collect_ofmonitor_util_c, 0},
		{(void*)(uintptr_t)sgx_ecall_collect_ofmonitor_util_r, 0},
		{(void*)(uintptr_t)sgx_ecall_cls_rule_is_loose_match, 0},
		{(void*)(uintptr_t)sgx_ecall_fet_ccfes_c, 0},
		{(void*)(uintptr_t)sgx_ecall_fet_ccfes_r, 0},
		{(void*)(uintptr_t)sgx_ecall_fet_ccfe_c, 0},
		{(void*)(uintptr_t)sgx_ecall_fet_ccfe_r, 0},
		{(void*)(uintptr_t)sgx_ecall_cls_lookup, 0},
		{(void*)(uintptr_t)sgx_ecall_cls_rule_priority, 0},
		{(void*)(uintptr_t)sgx_ecall_desfet_ccfes_c, 0},
		{(void*)(uintptr_t)sgx_ecall_desfet_ccfes_r, 0},
		{(void*)(uintptr_t)sgx_ecall_cls_rule_format, 0},
		{(void*)(uintptr_t)sgx_ecall_miniflow_expand, 0},
		{(void*)(uintptr_t)sgx_ecall_rule_calculate_tag, 0},
		{(void*)(uintptr_t)sgx_ecall_SGX_table_dpif, 0},
		{(void*)(uintptr_t)sgx_ecall_table_update_taggable, 0},
		{(void*)(uintptr_t)sgx_ecall_is_sgx_other_table, 0},
		{(void*)(uintptr_t)sgx_ecall_rule_calculate_tag_s, 0},
		{(void*)(uintptr_t)sgx_ecall_hidden_tables_check, 0},
		{(void*)(uintptr_t)sgx_ecall_oftable_set_name, 0},
		{(void*)(uintptr_t)sgx_ecall_minimask_get_vid_mask, 0},
		{(void*)(uintptr_t)sgx_ecall_miniflow_get_vid, 0},
		{(void*)(uintptr_t)sgx_ecall_ofproto_get_vlan_c, 0},
		{(void*)(uintptr_t)sgx_ecall_ofproto_get_vlan_r, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][59];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_myenclave_sample(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_myenclave_sample_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_myenclave_sample_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_myenclave_sample_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_myenclave_sample_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		memcpy(__tmp, str, _len_str);
		__tmp = (void *)((size_t)__tmp + _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

