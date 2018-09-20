#include <string.h>
#include <assert.h>
#include <libgen.h>
#include "sgx_utils.h"
#include "myenclave_u.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "sample.h"
#include <stdint.h>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
static int enclave_status=10;

/////////////////////////////////////////////////////////////////////////////
/* OCall functions */
void ocall_myenclave_sample(const char *str)
{
    /* Prox/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}




///////////////////////////////////////////////////////////////////////////
//API to trusted ecalls

//1. Creation and Initialization of tables
int sgx_ofproto_init_tables(int n_tables)
{
	printf("INSIDE SGX START......\n");
	int ecall_return;
	//ecall_myenclave_sample(global_eid, &ecall_return);
	if (enclave_status==10){
	    if(initialize_enclave(&global_eid) < 0){

	      return -1;
	    }
	    //Set the variable enclave_status to zero to avoid reinitialization of the enclave
	    enclave_status=0;
	    //initialize the tables
	    ecall_ofproto_init_tables(global_eid,n_tables);
	}
	else {
		printf("No need to initialize the container,.....\n");
	}

    //We perform another test:
     ecall_myenclave_sample(global_eid, &ecall_return);


     return 0;
}

//2 set the table to read_only "Hidden Table 254"
void SGX_readonly_set(int table_id){
	ecall_readonly_set(global_eid,table_id);
}
//2. This function will check if the table to which we want to add a flow is read_only
int SGX_istable_readonly(uint8_t table_id){
	int ecall_return;
	ecall_istable_readonly(global_eid,&ecall_return,table_id);
	return ecall_return;
}

//3.
void SGX_cls_rule_init(struct cls_rule * o_cls_rule,
		const struct match * match , unsigned int priority){
	ecall_cls_rule_init(global_eid,o_cls_rule,match,priority);
}

//4. SGX Classifier_rule_overlap
int SGX_cr_rule_overlaps(int table_id,struct cls_rule * o_cls_rule){
	int ecall_return;
	ecall_cr_rule_overlaps(global_eid,&ecall_return,table_id,o_cls_rule);
	return ecall_return;
}

//5. SGX_CLS_RULE_DESTROY
void SGX_cls_rule_destroy(struct cls_rule *o_cls_rule){
	ecall_cls_rule_destroy(global_eid,o_cls_rule);
}

//6. cls_rule_hash
uint32_t SGX_cls_rule_hash(const struct cls_rule *o_cls_rule, uint32_t basis){
	int ecall_return;
	ecall_cls_rule_hash(global_eid,&ecall_return,o_cls_rule,basis);
	return ecall_return;
}
//7. cls_rule_equal
int SGX_cls_rule_equal(const struct cls_rule *o_cls_rule_a,
		const struct cls_rule *o_cls_rule_b){
	int ecall_return;
	ecall_cls_rule_equal(global_eid,&ecall_return,o_cls_rule_a,o_cls_rule_b);
	return ecall_return;
}

//8. classifier_replace
void SGX_classifier_replace(int table_id,struct cls_rule* o_cls_rule,struct cls_rule ** cls_rule_rtrn){
	ecall_classifier_replace(global_eid,table_id,o_cls_rule,cls_rule_rtrn);
}

//9 rule_get_flags
enum oftable_flags SGX_rule_get_flags (int table_id){
	enum oftable_flags m;
	ecall_rule_get_flags(global_eid, &m,table_id);
	return m;
}
//10. classifier count of cls_rules
int SGX_cls_count(int table_id){
	int ecall_return;
	ecall_cls_count(global_eid,&ecall_return,table_id);
	return ecall_return;
}

//11. is eviction_fields in the table with table_id enabled?
int SGX_eviction_fields_enable(int table_id){
	int result;
	ecall_eviction_fields_enable(global_eid,&result,table_id);
	return result;
}

//12.Add a rule to a eviction group
size_t SGX_evg_add_rule(int table_id, struct cls_rule *o_cls_rule,uint32_t priority,
		uint32_t rule_evict_prioriy,struct heap_node rule_evg_node){

	size_t result;
	ecall_evg_add_rule(global_eid,&result,table_id,o_cls_rule,priority,
			rule_evict_prioriy,rule_evg_node);

	return result;
}

//13. void ecall_evg_group_resize
void SGX_evg_group_resize(int table_id,struct cls_rule *o_cls_rule,size_t priority){
	ecall_evg_group_resize(global_eid,table_id,o_cls_rule,priority);
}

//14. Remove the evict group where a rule belongs to
int SGX_evg_remove_rule(int table_id,struct cls_rule *o_cls_rule){
	int result;
	ecall_evg_remove_rule(global_eid,&result,table_id,o_cls_rule);
	return result;
}

//15. Removes a cls_rule from the classifier
void SGX_cls_remove(int table_id,struct cls_rule *o_cls_rule){
	ecall_cls_remove(global_eid, table_id,o_cls_rule);
}

//16. SGX choose a cls_rule to evict from table
void SGX_choose_rule_to_evict(int table_id,struct cls_rule *o_cls_rule){
	ecall_choose_rule_to_evict(global_eid,table_id,o_cls_rule);
}

//17.
void SGX_choose_rule_to_evict_p(int table_id,struct cls_rule *o_cls_rule){
	ecall_choose_rule_to_evict_p(global_eid,table_id,o_cls_rule);
}

//18 returns table max flow
unsigned int SGX_table_mflows(int table_id){
	unsigned int result;
	ecall_table_mflows(global_eid,&result,table_id);
	return result;
}

//19 set table max flow to value
void SGX_table_mflows_set(int table_id,unsigned int value){
	ecall_table_mflows_set(global_eid,table_id,value);
}

//19 minimatch_expand
void SGX_minimatch_expand(struct cls_rule *o_cls_rule,struct match *dst){

	ecall_minimatch_expand(global_eid,o_cls_rule,dst);
}

//20. cls_rule priority
unsigned int SGX_cr_priority(struct cls_rule *o_cls_rule){
	unsigned result;
	ecall_cr_priority(global_eid,&result,o_cls_rule);
	return result;
}

//21  classifier find match exactly
void SGX_cls_find_match_exactly(int table_id,
		const struct match *target,
		unsigned int priority,struct cls_rule **o_cls_rule){

	ecall_cls_find_match_exactly(global_eid,table_id,target,priority,o_cls_rule);
}

//22. SGX FOR_EACH_MATCHING_TABLE + CLS_CURSOR_FOR_EACH (count and request

//22.1 Count
int SGX_femt_ccfe_c(int ofproto_n_tables,uint8_t table_id,const struct match *match){
	int result;
	ecall_femt_ccfe_c(global_eid,&result,ofproto_n_tables,table_id,match);
	return result;
}

//22.2 Request
void SGX_femt_ccfe_r(int ofproto_n_tables,struct cls_rule **buf,int elem,uint8_t table_id,const struct match *match){
	ecall_femt_ccfe_r(global_eid,ofproto_n_tables,buf,elem,table_id,match);
}

//23. SGX FOR_EACH_MATCHING_TABLE get the rules

//23.1 Count
int SGX_ecall_femt_c(int ofproto_n_tables,uint8_t table_id,const struct match *match,unsigned int priority){
	int buf_size;
    ecall_femt_c(global_eid,&buf_size,ofproto_n_tables,table_id,match,priority);
    return buf_size;
}

//23.2 Request
void SGX_ecall_femt_r(int ofproto_n_tables,struct cls_rule **buf,int elem,uint8_t table_id,const struct match *match,unsigned int priority)
{
	ecall_femt_r(global_eid,ofproto_n_tables,buf,elem,table_id,match,priority);
}

//24 CLS_CURSOR_FOR_EACH
//24.1 Count
int SGX_ccfe_c(int table_id){
	int buffer_size;
	ecall_ccfe_c(global_eid,&buffer_size,table_id);
	return buffer_size;
}
//24.2 Request
void SGX_ccfe_r(struct cls_rule **buf,int elem,int table_id){
	ecall_ccfe_r(global_eid,buf,elem,table_id);
}

int SGX_collect_ofmonitor_util_c(int ofproto_n_tables,int table_id,const struct minimatch *match){
	int count;
	ecall_collect_ofmonitor_util_c(global_eid,&count,ofproto_n_tables,table_id,match);
	return count;
}

void SGX_collect_ofmonitor_util_r(int ofproto_n_tables,struct cls_rule **buf,int elem,int table_id,const struct minimatch *match){
 ecall_collect_ofmonitor_util_r(global_eid,ofproto_n_tables,buf,elem,table_id,match);
}



//25. One Part of Enable_eviction
void SGX_oftable_enable_eviction(int table_id,const struct mf_subfield *fields,size_t n_fields,uint32_t random_v){
	ecall_oftable_enable_eviction(global_eid,table_id,fields,n_fields,random_v);
}

//25.1
void SGX_oftable_disable_eviction(int table_id){
	ecall_oftable_disable_eviction(global_eid,table_id);
}

//26 oftable destroy
void SGX_ofproto_destroy(void){
	ecall_ofproto_destroy(global_eid);
}

//27 Count total number of rules
unsigned int SGX_total_rules(void){
	unsigned int n_rules;
	ecall_total_rules(global_eid,&n_rules);
	return n_rules;
}

//28 Copy the name of the table
void SGX_table_name(int table_id,char *buf,size_t len){
 ecall_table_name(global_eid,table_id,buf,len);
}

//29 loose_match
int SGX_cls_rule_is_loose_match(struct cls_rule *o_cls_rule,const struct minimatch *criteria){
	int result;
 	ecall_cls_rule_is_loose_match(global_eid,&result,o_cls_rule,criteria);
 	return result;
}

//30. Dependencies for ofproto_flush__
int SGX_fet_ccfes_c(void){
	int count;
	ecall_fet_ccfes_c(global_eid,&count);
	return count;
}

//30.1
void SGX_fet_ccfes_r(struct cls_rule **buf,int elem){
	ecall_fet_ccfes_r(global_eid,buf,elem);
}

//31 Dependencies for ofproto_get_all_flows
int SGX_fet_ccfe_c(void){
	int count;
	ecall_fet_ccfe_c(global_eid,&count);
	return count;
}

//31.2 REQUEST
void SGX_fet_ccfe_r(struct cls_rule **buf,int elem){
	ecall_fet_ccfe_r(global_eid,buf,elem);
}

//33 Classifier_lookup
void SGX_cls_lookup(struct cls_rule **o_cls_rule,int table_id,const struct flow *flow,
		struct flow_wildcards *wc){
  ecall_cls_lookup(global_eid,o_cls_rule,table_id,flow,wc);
}

//34. CLS_RULE priority
unsigned int SGX_cls_rule_priority(struct cls_rule *o_cls_rule){
	unsigned int priority;
	ecall_cls_rule_priority(global_eid,&priority,o_cls_rule);
	return priority;
}

//Dependencies for destroy
int SGX_desfet_ccfes_c(void){
	int count;
	ecall_desfet_ccfes_c(global_eid,&count);
	return count;
}

//2.
void SGX_desfet_ccfes_r(struct cls_rule **buf,int elem){
	ecall_desfet_ccfes_r(global_eid,buf,elem);
}

//37. CLS_RULE_DEPENDENCIES
unsigned int SGX_cls_rule_format(const struct cls_rule *o_cls_rule,struct match *megamatch){
	unsigned int priority;
	ecall_cls_rule_format(global_eid,&priority,o_cls_rule,megamatch);
	return priority;
}

//38 miniflow_expand inside the enclave
//This functions copies from the enclave information into the struct flow.
void SGX_miniflow_expand(struct cls_rule *o_cls_rule,struct flow *flow){
	ecall_miniflow_expand(global_eid,o_cls_rule,flow);
}

//39. Rule_calculate tag this needs to check the result and if not zero
//Calculate the tag_create deterministics
uint32_t SGX_rule_calculate_tag(struct cls_rule *o_cls_rule,const struct flow *flow,int table_id){
	uint32_t hash;
	ecall_rule_calculate_tag(global_eid,&hash,o_cls_rule,flow,table_id);
	return hash;
}

//This Functions are used for the table_dpif in ofproto_dpif {

//1.
void SGX_table_dpif_init(int n_tables){
	ecall_SGX_table_dpif(global_eid,n_tables);
}

//2.
int SGX_table_update_taggable(uint8_t table_id){
	int todo;
	ecall_table_update_taggable(global_eid,&todo,table_id);
	return todo;
}

//3.
int SGX_is_sgx_other_table(int id){
	int result;
	ecall_is_sgx_other_table(global_eid,&result,id);
	return result;
}

//4
uint32_t SGX_rule_calculate_tag_s(int id,const struct flow *flow,uint32_t secret){
	uint32_t hash;
	ecall_rule_calculate_tag_s(global_eid,&hash,id,flow,secret);
	return hash;
}

void sgx_oftable_check_hidden(void){
	ecall_hidden_tables_check(global_eid);
}

void SGX_oftable_set_name(int table_id, char *name){
	ecall_oftable_set_name(global_eid,table_id, name);
}

//These functions are going to be used by ofopgroup_complete
uint16_t SGX_minimask_get_vid_mask(struct cls_rule *o_cls_rule){
	uint16_t result;
	ecall_minimask_get_vid_mask(global_eid,&result,o_cls_rule);
	return result;
}

uint16_t SGX_miniflow_get_vid(struct cls_rule *o_cls_rule){
	uint16_t result;
	 ecall_miniflow_get_vid(global_eid,&result,o_cls_rule);
	 return result;
}

//These functions are depencencies for ofproto_get_vlan_usage
//1. Count
int SGX_ofproto_get_vlan_usage_c(void){
	int count;
	ecall_ofproto_get_vlan_c(global_eid,&count);
	return count;
}

//2. Allocate
void SGX_ofproto_get_vlan_usage__r(uint16_t *buf,int elem){
	ecall_ofproto_get_vlan_r(global_eid,buf,elem);
}











