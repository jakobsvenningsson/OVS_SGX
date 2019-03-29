#include "call-table.h"
#include "ofproto-provider.h"

void execute_function(int function, argument_list *args, return_value *ret) {
  switch(function) {
    case ECALL_ISTABLE_READONLY:
			*((int *) ret->val) = ecall_istable_readonly(*((uint8_t *) args->arg1));
      break;
		case ECALL_CLS_RULE_INIT:
		 	ecall_cls_rule_init((struct cls_rule *) args->arg1,
				(const struct match *) args->arg2 , *((unsigned int *) args->arg3));
			break;
		case ECALL_CLS_RULE_DESTROY:
			ecall_cls_rule_destroy((struct cls_rule *) args->arg1);
			break;
		case ECALL_CR_RULE_OVERLAPS:
				*((int *) ret->val) = ecall_cr_rule_overlaps(*((int *) args->arg1), (struct cls_rule *) args->arg2);
			break;
		case ECALL_READONLY_SET:
			ecall_readonly_set(*((uint8_t *) args->arg1));
			break;
		case ECALL_OFTABLE_SET_NAME:
			ecall_oftable_set_name(*((int *) args->arg1), (char *) args->arg2);
			break;
		case ECALL_OFTABLE_DISABLE_EVICTION:
			ecall_oftable_disable_eviction(*((int *) args->arg1));
			break;
		case ECALL_TABLE_MFLOWS_SET:
			ecall_table_mflows_set(*((int *) args->arg1), *((unsigned int *) args->arg2));
			break;
		case ECALL_CLS_COUNT:
			*((int *) ret->val) = ecall_cls_count(*((int *) args->arg1));
			break;
		case ECALL_TABLE_MFLOWS:
			*((unsigned int *) ret->val) = ecall_table_mflows(*((int *) args->arg1));
			break;
		case ECALL_EVICTION_FIELDS_ENABLE:
			*((int *) ret->val) = ecall_eviction_fields_enable(*((int *) args->arg1));
			break;
		case ECALL_FET_CCFES_C:
			*((int *) ret->val) = ecall_fet_ccfes_c();
			break;
		case ECALL_FET_CCFES_R:
			ecall_fet_ccfes_r((struct cls_rule **) args->arg1, *((int *) args->arg2));
			break;
		case ECALL_OFPROTO_DESTROY:
			ecall_ofproto_destroy();
			break;
		case ECALL_TOTAL_RULES:
			*((unsigned int *) ret->val) = ecall_total_rules();
			break;
		case ECALL_CLS_FIND_MATCH_EXACTLY:
			ecall_cls_find_match_exactly(*((int *) args->arg1), (const struct match *) args->arg2, *((unsigned int *) args->arg3), (struct cls_rule **) args->arg4);
			break;
		case ECALL_CR_PRIORITY:
			*((unsigned int *) ret->val) = ecall_cr_priority((struct cls_rule *) args->arg1);
			break;
		case ECALL_RULE_GET_FLAGS:
			*((enum oftable_flags *) ret->val) = ecall_rule_get_flags(*((int *) args->arg1));
			break;
		case ECALL_TABLE_NAME:
			ecall_table_name(*((int *) args->arg1), (char *) args->arg2, *((size_t *) args->arg1));
			break;
		case ECALL_FEMT_CCFE_C:
			ecall_femt_ccfe_c(*((int *) args->arg1), *((uint8_t *) args->arg2), (const struct match *) args->arg3);
			break;
		case ECALL_FEMT_CCFE_R:
			ecall_femt_ccfe_r(*((int *) args->arg1),
												(struct cls_rule **) args->arg2,
												*((int *) args->arg3),
												*((uint8_t *) args->arg4),
												(const struct match *) args->arg5);
			break;
		case ECALL_MINIMATCH_EXPAND:
			ecall_minimatch_expand((struct cls_rule *) args->arg1, (struct match *) args->arg2);
			break;
		case ECALL_CLS_RULE_FORMAT:
			*((unsigned int *) ret->val) = ecall_cls_rule_format((const struct cls_rule *) args->arg1, (struct match *) args->arg2);
			break;
		case ECALL_FET_CCFE_C:
			*((int *) ret->val) = ecall_fet_ccfe_c();
			break;
		case ECALL_FET_CCFE_R:
			ecall_fet_ccfe_r((struct cls_rule **) args->arg1, *((int *) args->arg2));
			break;
		case ECALL_CLS_RULE_HASH:
			ecall_cls_rule_hash((const struct cls_rule *) args->arg1, *((uint32_t *) args->arg2));
			break;
		case ECALL_CLS_RULE_EQUAL:
			*((int *) ret->val) = ecall_cls_rule_equal((const struct cls_rule *) args->arg1, (const struct cls_rule *) args->arg2);
			break;
		case ECALL_CHOOSE_RULE_TO_EVICT:
		 	ecall_choose_rule_to_evict(*((int *) args->arg1), (struct cls_rule *) args->arg2);
			break;
		case ECALL_CHOOSE_RULE_TO_EVICT_P:
		 ecall_choose_rule_to_evict_p(*((int *) args->arg1), (struct cls_rule *) args->arg2);
		 break;
		case ECALL_COLLECT_OFMONITOR_UTIL_C:
			*((int *) ret->val) = ecall_collect_ofmonitor_util_c(*((int *) args->arg1), *((int *) args->arg2), (const struct minimatch *) args->arg3);
			break;
		case ECALL_COLLECT_OFMONITOR_UTIL_R:
			ecall_collect_ofmonitor_util_r(*((int *) args->arg1), (struct cls_rule **) args->arg2, *((int *) args->arg3), *((int *) args->arg4), (const struct minimatch *) args->arg5);
			break;
		case ECALL_CLS_RULE_IS_LOOSE_MATCH:
			*((int *) ret->val) = ecall_cls_rule_is_loose_match((struct cls_rule *) args->arg1, (const struct minimatch *) args->arg2);
			break;
		case ECALL_MINIMASK_GET_VID_MASK:
			*((uint16_t *) ret->val) = ecall_minimask_get_vid_mask((struct cls_rule *) args->arg1);
			break;
		case ECALL_MINIFLOW_GET_VID:
			*((uint16_t *) ret->val) = ecall_miniflow_get_vid((struct cls_rule *) args->arg1);
			break;
		case ECALL_EVG_GROUP_RESIZE:
			ecall_evg_group_resize(*((int *) args->arg1), (struct cls_rule *) args->arg2, *((size_t *) args->arg3));
			break;
		case ECALL_EVG_ADD_RULE:
			*((size_t *) ret->val) = ecall_evg_add_rule(*((int *) args->arg1),
																									(struct cls_rule *) args->arg2,
																									*((uint32_t *) args->arg3),
																									*((uint32_t *) args->arg4),
																									*((struct heap_node *) args->arg5));
			break;
		case ECALL_OFTABLE_ENABLE_EVICTION:
			ecall_oftable_enable_eviction(*((int *) args->arg1),
																		(const struct mf_subfield *) args->arg2,
																		*((size_t *) args->arg3),
																		*((uint32_t *) args->arg4));
			break;
		case ECALL_CCFE_C:
			*((int *) ret->val) = ecall_ccfe_c(*((int *) args->arg1));
			break;
		case ECALL_CCFE_R:
			ecall_ccfe_r((struct cls_rule **) args->arg1,
									*((int *) args->arg2),
									*((int *) args->arg3));
			break;
		case ECALL_CLS_REMOVE:
			ecall_cls_remove(*((int *) args->arg1), (struct cls_rule *) args->arg2);
			break;
		case ECALL_CLASSIFIER_REPLACE:
			ecall_classifier_replace(*((int *) args->arg1),
															(struct cls_rule *) args->arg2,
															(struct cls_rule **) args->arg3);
			break;
		case ECALL_OFPROTO_GET_VLAN_C:
			*((int *) ret->val) = ecall_ofproto_get_vlan_c();
			break;
		case ECALL_OFPROTO_GET_VLAN_R:
			ecall_ofproto_get_vlan_r((uint16_t *) args->arg1,
															*((int *) args->arg2));
			break;
		case ECALL_FEMT_C:
			*((int *) ret->val) =  ecall_femt_ccfe_c(*((int *) args->arg1),
																							 *((uint8_t *) args->arg2),
																							 (const struct match *) args->arg3);
			break;
		case ECALL_FEMT_R:
			ecall_femt_r(*((int *) args->arg1),
									(struct cls_rule **) args->arg2,
									*((int *) args->arg3),
									*((uint8_t *) args->arg4),
									(const struct match *) args->arg5,
									*((unsigned int *) args->arg6));
			break;
		case ECALL_HIDDEN_TABLES_CHECK:
			ecall_hidden_tables_check();
			break;
		case ECALL_MINIFLOW_EXPAND:
		 	ecall_miniflow_expand((struct cls_rule *) args->arg1, (struct flow *) args->arg2);
			break;
		case ECALL_RULE_CALCULATE_TAG:
			*((uint32_t *) ret->val) = ecall_rule_calculate_tag((struct cls_rule *) args->arg1, (const struct flow *) args->arg2, *((int *) args->arg3));
			break;
		case ECALL_TABLE_UPDATE_TAGGABLE:
			*((int *) ret->val) = ecall_table_update_taggable(*((uint8_t *) args->arg1));
			break;
		case ECALL_IS_SGX_OTHER_TABLE:
		 	*((int *) ret->val) = ecall_is_sgx_other_table(*((int *) args->arg1));
			break;
		case ECALL_CLS_LOOKUP:
		 	ecall_cls_lookup((struct cls_rule **) args->arg1, *((int *) args->arg2), (const struct flow *) args->arg3, (struct flow_wildcards *) args->arg4);
			break;
		case ECALL_SGX_TABLE_DPIF:
			ecall_SGX_table_dpif(*((int *) args->arg1));
			break;
		case ECALL_EVG_REMOVE_RULE:
		 	*((int *) ret->val) =ecall_evg_remove_rule(*((int *) args->arg1),
																								(struct cls_rule *) args->arg2);
			break;
		case ECALL_DESTROY_RULE_IF_OVERLAPS:
			ecall_destroy_rule_if_overlaps(*((int *) args->arg1), (struct cls_rule *) args->arg2);
			break;
		case ECALL_GET_RULE_TO_EVICT_IF_NECCESARY:
			*((bool *) ret->val) = ecall_get_rule_to_evict_if_neccesary(*((int *) args->arg1), (struct cls_rule *) args->arg2);
			break;
		case ECALL_MINIFLOW_EXPAND_AND_TAG:
			*((uint32_t *) ret->val) = ecall_miniflow_expand_and_tag((struct cls_rule *) args->arg1, (struct flow *) args->arg2, *((int *) args->arg3));
			break;
		case ECALL_ALLOCATE_CLS_RULE_IF_NOT_READ_ONLY:
			*((bool *) ret->val) = ecall_allocate_cls_rule_if_not_read_only(*((int *) args->arg1), (struct cls_rule *) args->arg2, (struct match *) args->arg3, *((unsigned int *) args->arg4));
			break;
    case ECALL_CLASSIFIER_REPLACE_IF_MODIFIABLE:
      ecall_classifer_replace_if_modifiable(*((int *) args->arg1),
                                            (struct cls_rule *) args->arg2,
                                            (struct cls_rule **) args->arg3,
                                            (bool *) args->arg4);
      break;
    default:
      printf("Error, no matching switch case for %d.\n", function);
  }
}
