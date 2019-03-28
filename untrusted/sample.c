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


#include <pthread.h>

#include "spinlock.h"


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

static int enclave_status=10;



static async_ecall ctx;

void *ecall_polling_thread(void *vargp) {
  printf("Running polling thread.\n");
  int ecall_return;
  MAKE_ECALL_ARGS(start_poller, &ecall_return, &ctx);
  if (ecall_return == 0) {
    printf("Application ran with success\n");
  }
  else {
      printf("Application failed %d \n", ecall_return);
  }
}

static inline void _mm_pause(void) __attribute__((always_inline));
static inline void _mm_pause(void)
{
    __asm __volatile(
        "pause"
    );
}

void make_hotcall(async_ecall *ctx, int function, argument_list *args, return_value *ret) {
  ctx->function = function;
  ctx->args = args;
  ctx->ret = ret;
  ctx->run = true;
  ctx->is_done = false;
  while(1) {
    sgx_spin_lock(&ctx->spinlock);
    if(ctx->is_done) {
      sgx_spin_unlock(&ctx->spinlock);
      break;
    }
    sgx_spin_unlock(&ctx->spinlock);
    for(int i = 0; i<3; ++i)
      _mm_pause();
  }
}

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
   //ecall_myenclave_sample(global_eid, &ecall_return);

   #ifdef HOTCALL
     puts("HOTCALLS ENABLED STARTING THREAD.");
     pthread_t thread_id;
     pthread_create(&thread_id, NULL, ecall_polling_thread, NULL);
   #else
    puts("NO HOTCALLS.");
   #endif

  return 0;
}




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


//2 set the table to read_only "Hidden Table 254"
void SGX_readonly_set(int table_id){
	ecall_readonly_set(global_eid,table_id);
}
//2. This function will check if the table to which we want to add a flow is read_only
int SGX_istable_readonly(uint8_t table_id){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 1,
      .arg1 = (void *) &table_id,
    };

    int ecall_return;
    return_value ret = {
      .allocated_size = 0,
      .val = (void *) &ecall_return
    };

    make_hotcall(&ctx, ECALL_ISTABLE_READONLY, &args, &ret);

    printf("function %d return  %d\n",ECALL_ISTABLE_READONLY, ecall_return);
  	return ecall_return;
  #else
    int ecall_return;
    ecall_istable_readonly(global_eid, &ecall_return,table_id);
    return ecall_return;
  #endif
}

//3.
void SGX_cls_rule_init(struct cls_rule * o_cls_rule,
		const struct match * match , unsigned int priority){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 3,
      .arg1 = (void *) o_cls_rule,
      .arg2 = (void *) match,
      .arg3 = (void *) &priority,
    };
    make_hotcall(&ctx, ECALL_CLS_RULE_INIT, &args, NULL);
  #else
    ecall_cls_rule_init(global_eid, o_cls_rule, match, priority);
  #endif
}

//4. SGX Classifier_rule_overlap
int SGX_cr_rule_overlaps(int table_id,struct cls_rule * o_cls_rule){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 1,
      .arg1 = &table_id,
      .arg2 = (void *) &o_cls_rule,
    };

    int ecall_return;
    return_value ret = {
      .allocated_size = 0,
      .val = (void *) &ecall_return
    };
    make_hotcall(&ctx, ECALL_CR_RULE_OVERLAPS, &args, &ret);
  	return ecall_return;
  #else
    int ecall_return;
    ecall_cr_rule_overlaps(global_eid, &ecall_return, table_id, o_cls_rule);
    return ecall_return;
  #endif
}

//5. SGX_CLS_RULE_DESTROY
void SGX_cls_rule_destroy(struct cls_rule *o_cls_rule){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 1,
      .arg1 = (void *) o_cls_rule,
    };
    make_hotcall(&ctx, ECALL_CLS_RULE_DESTROY, &args, NULL);
  #else
    ecall_cls_rule_destroy(global_eid, o_cls_rule);
  #endif
}

//6. cls_rule_hash
uint32_t SGX_cls_rule_hash(const struct cls_rule *o_cls_rule, uint32_t basis){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 2,
      .arg1 = (void *) o_cls_rule,
      .arg2 = (void *) &basis,
    };
    uint32_t ecall_return;
    return_value ret = {
      .allocated_size = 0,
      .val = (void *) &ecall_return
    };
    make_hotcall(&ctx, ECALL_CLS_RULE_HASH, &args, &ret);
    return ecall_return;
  #else
	int ecall_return;
	ecall_cls_rule_hash(global_eid,&ecall_return,o_cls_rule,basis);
	return ecall_return;
  #endif
}
//7. cls_rule_equal
int SGX_cls_rule_equal(const struct cls_rule *o_cls_rule_a,
		const struct cls_rule *o_cls_rule_b){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 2,
      .arg1 = (void *) o_cls_rule_a,
      .arg2 = (void *) o_cls_rule_b,
    };
    int ecall_return;
    return_value ret = {
      .allocated_size = 0,
      .val = (void *) &ecall_return
    };
    make_hotcall(&ctx, ECALL_CLS_RULE_EQUAL, &args, &ret);
    return ecall_return;
  #else
	int ecall_return;
	ecall_cls_rule_equal(global_eid,&ecall_return,o_cls_rule_a,o_cls_rule_b);
	return ecall_return;
  #endif
}

//8. classifier_replace
void SGX_classifier_replace(int table_id,struct cls_rule* o_cls_rule,struct cls_rule ** cls_rule_rtrn){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 3,
      .arg1 = (void *) &table_id,
      .arg2 = (void *) o_cls_rule,
      .arg3 = (void *) cls_rule_rtrn,
    };
    make_hotcall(&ctx, ECALL_CLASSIFIER_REPLACE, &args, NULL);
  #else
    ecall_classifier_replace(global_eid,table_id,o_cls_rule,cls_rule_rtrn);
  #endif
}

//9 rule_get_flags
enum oftable_flags SGX_rule_get_flags (int table_id){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 1,
      .arg1 = (void *) &table_id,
    };
    enum oftable_flags ecall_return;
    return_value ret = {
      .allocated_size = 0,
      .val = (void *) &ecall_return
    };
    make_hotcall(&ctx, ECALL_RULE_GET_FLAGS, &args, &ret);
    return ecall_return;
  #else
    enum oftable_flags m;
    ecall_rule_get_flags(global_eid, &m,table_id);
    return m;
  #endif
}
//10. classifier count of cls_rules
int SGX_cls_count(int table_id){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 1,
      .arg1 = (void *) &table_id,
    };
    int ecall_return;
    return_value ret = {
      .allocated_size = 0,
      .val = (void *) &ecall_return
    };
    make_hotcall(&ctx, ECALL_CLS_COUNT, &args, &ret);
    return ecall_return;
  #else
    int ecall_return;
  	ecall_cls_count(global_eid,&ecall_return,table_id);
  	return ecall_return;
  #endif
}

//11. is eviction_fields in the table with table_id enabled?
int SGX_eviction_fields_enable(int table_id){
	#ifdef HOTCALL
    argument_list args = {
      .n_args = 1,
      .arg1 = (void *) &table_id,
    };
    int ecall_return;
    return_value ret = {
      .allocated_size = 0,
      .val = (void *) &ecall_return
    };
    make_hotcall(&ctx, ECALL_EVICTION_FIELDS_ENABLE, &args, &ret);
    return ecall_return;
  #else
    int result;
    ecall_eviction_fields_enable(global_eid,&result,table_id);
    return result;
  #endif
}

//12.Add a rule to a eviction group
size_t SGX_evg_add_rule(int table_id, struct cls_rule *o_cls_rule,uint32_t priority,
  uint32_t rule_evict_prioriy,struct heap_node rule_evg_node){
	#ifdef HOTCALL
    argument_list args = {
      .n_args = 5,
      .arg1 = (void *) &table_id,
      .arg2 = (void *) o_cls_rule,
      .arg3 = (void *) &priority,
      .arg4 = (void *) &rule_evict_prioriy,
      .arg5 = (void *) &rule_evg_node,
    };
    size_t ecall_return;
    return_value ret = {
      .allocated_size = 0,
      .val = (void *) &ecall_return
    };
    make_hotcall(&ctx, ECALL_EVG_ADD_RULE, &args, &ret);
    return ecall_return;
  #else
    size_t result;
    ecall_evg_add_rule(global_eid,&result,table_id,o_cls_rule,priority,
        rule_evict_prioriy,rule_evg_node);
    return result;
  #endif
}

//13. void ecall_evg_group_resize
void SGX_evg_group_resize(int table_id,struct cls_rule *o_cls_rule,size_t priority){
  #ifdef HOTCALL
  argument_list args = {
    .n_args = 3,
    .arg1 = (void *) &table_id,
    .arg2 = (void *) o_cls_rule,
    .arg3 = (void *) &priority,
  };
  make_hotcall(&ctx, ECALL_EVG_GROUP_RESIZE, &args, NULL);
  #else
    ecall_evg_group_resize(global_eid,table_id,o_cls_rule,priority);
  #endif
}

//14. Remove the evict group where a rule belongs to
int SGX_evg_remove_rule(int table_id,struct cls_rule *o_cls_rule){
	#ifdef HOTCALL
  argument_list args = {
    .n_args = 2,
    .arg1 = (void *) &table_id,
    .arg2 = (void *) o_cls_rule,
  };
  int ecall_return;
  return_value ret = {
    .allocated_size = 0,
    .val = (void *) &ecall_return
  };
  make_hotcall(&ctx, ECALL_EVG_REMOVE_RULE, &args, &ret);
  return ecall_return;
  #else
    int result;
  	ecall_evg_remove_rule(global_eid,&result,table_id,o_cls_rule);
  	return result;
  #endif
}

//15. Removes a cls_rule from the classifier
void SGX_cls_remove(int table_id,struct cls_rule *o_cls_rule){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 2,
      .arg1 = (void *) &table_id,
      .arg2 = (void *) o_cls_rule,
    };
    make_hotcall(&ctx, ECALL_CLS_REMOVE, &args, NULL);
  #else
    ecall_cls_remove(global_eid, table_id,o_cls_rule);
  #endif
}

//16. SGX choose a cls_rule to evict from table
void SGX_choose_rule_to_evict(int table_id,struct cls_rule *o_cls_rule){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 2,
      .arg1 = (void *) &table_id,
      .arg2 = (void *) o_cls_rule,
    };
    make_hotcall(&ctx, ECALL_CHOOSE_RULE_TO_EVICT, &args, NULL);
  #else
    ecall_choose_rule_to_evict(global_eid,table_id,o_cls_rule);
  #endif
}

//17.
void SGX_choose_rule_to_evict_p(int table_id,struct cls_rule *o_cls_rule){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 2,
      .arg1 = (void *) &table_id,
      .arg2 = (void *) o_cls_rule,
    };
    make_hotcall(&ctx, ECALL_CHOOSE_RULE_TO_EVICT_P, &args, NULL);
  #else
  ecall_choose_rule_to_evict_p(global_eid,table_id,o_cls_rule);
  #endif
}

//18 returns table max flow
unsigned int SGX_table_mflows(int table_id){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 1,
      .arg1 = (void *) &table_id,
    };
    unsigned int ecall_return;
    return_value ret = {
      .allocated_size = 0,
      .val = (void *) &ecall_return
    };
    make_hotcall(&ctx, ECALL_TABLE_MFLOWS, &args, &ret);
    return ecall_return;
  #else
    unsigned int result;
    ecall_table_mflows(global_eid,&result,table_id);
    return result;
  #endif
}

//19 set table max flow to value
void SGX_table_mflows_set(int table_id,unsigned int value){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 2,
      .arg1 = (void *) &table_id,
      .arg2 = (void *) &value,
    };
    make_hotcall(&ctx, ECALL_TABLE_MFLOWS_SET, &args, NULL);
  #else
    ecall_table_mflows_set(global_eid,table_id,value);
  #endif
}

//19 minimatch_expand
void SGX_minimatch_expand(struct cls_rule *o_cls_rule,struct match *dst){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 2,
      .arg1 = (void *) o_cls_rule,
      .arg2 = (void *) dst,
    };
    make_hotcall(&ctx, ECALL_MINIMATCH_EXPAND, &args, NULL);
  #else
    ecall_minimatch_expand(global_eid,o_cls_rule,dst);
  #endif
}

//20. cls_rule priority
unsigned int SGX_cr_priority(struct cls_rule *o_cls_rule){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 1,
      .arg1 = (void *) o_cls_rule,
    };
    unsigned int ecall_return;
    return_value ret = {
      .allocated_size = 0,
      .val = (void *) &ecall_return
    };
    make_hotcall(&ctx, ECALL_CR_PRIORITY, &args, &ret);
    return ecall_return;
  #else
    unsigned result;
  	ecall_cr_priority(global_eid,&result,o_cls_rule);
  	return result;
  #endif
}

//21  classifier find match exactly
void SGX_cls_find_match_exactly(int table_id,
                            		const struct match *target,
                            		unsigned int priority,
                                struct cls_rule **o_cls_rule){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 3,
      .arg1 = (void *) &table_id,
      .arg2 = (void *) target,
      .arg3 = (void *) &priority,
      .arg4 = (void *) o_cls_rule,
    };
    make_hotcall(&ctx, ECALL_CLS_FIND_MATCH_EXACTLY, &args, NULL);
  #else
	   ecall_cls_find_match_exactly(global_eid,table_id,target,priority,o_cls_rule);
  #endif
}

//22. SGX FOR_EACH_MATCHING_TABLE + CLS_CURSOR_FOR_EACH (count and request

//22.1 Count
int SGX_femt_ccfe_c(int ofproto_n_tables,uint8_t table_id,const struct match *match){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 3,
      .arg1 = (void *) &ofproto_n_tables,
      .arg2 = (void *) &table_id,
      .arg3 = (void *) match,

    };
    int ecall_return;
    return_value ret = {
      .allocated_size = 0,
      .val = (void *) &ecall_return
    };
    make_hotcall(&ctx, ECALL_FET_CCFE_C, &args, &ret);
    return ecall_return;
  #else
    int result;
    ecall_femt_ccfe_c(global_eid,&result,ofproto_n_tables,table_id,match);
    return result;
  #endif
}

//22.2 Request
void SGX_femt_ccfe_r(int ofproto_n_tables,struct cls_rule **buf,int elem,uint8_t table_id,const struct match *match){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 5,
      .arg1 = (void *) &ofproto_n_tables,
      .arg2 = (void *) buf,
      .arg3 = (void *) &elem,
      .arg4 = (void *) &table_id,
      .arg5 = (void *) match,
    };
    make_hotcall(&ctx, ECALL_FEMT_CCFE_R, &args, NULL);
  #else
    ecall_femt_ccfe_r(global_eid,ofproto_n_tables,buf,elem,table_id,match);
  #endif
}

//23. SGX FOR_EACH_MATCHING_TABLE get the rules

//23.1 Count
int SGX_ecall_femt_c(int ofproto_n_tables,uint8_t table_id,const struct match *match,unsigned int priority){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 4,
      .arg1 = (void *) &ofproto_n_tables,
      .arg2 = (void *) &table_id,
      .arg3 = (void *) match,
      .arg4 = (void *) &priority,
    };
    int ecall_return;
    return_value ret = {
      .allocated_size = 0,
      .val = (void *) &ecall_return
    };
    make_hotcall(&ctx, ECALL_FEMT_C, &args, &ret);
    return ecall_return;
  #else
    int buf_size;
    ecall_femt_c(global_eid,&buf_size,ofproto_n_tables,table_id,match,priority);
    return buf_size;
  #endif
}

//23.2 Request
void SGX_ecall_femt_r(int ofproto_n_tables,
                      struct cls_rule **buf,
                      int elem,
                      uint8_t table_id,
                      const struct match *match,
                      unsigned int priority)
{
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 6,
      .arg1 = (void *) &ofproto_n_tables,
      .arg2 = (void *) buf,
      .arg3 = (void *) &elem,
      .arg4 = (void *) &table_id,
      .arg5 = (void *) match,
      .arg6 = (void *) &priority,
    };
    make_hotcall(&ctx, ECALL_FEMT_R, &args, NULL);
  #else
    ecall_femt_r(global_eid,ofproto_n_tables,buf,elem,table_id,match,priority);
  #endif
}

//24 CLS_CURSOR_FOR_EACH
//24.1 Count
int SGX_ccfe_c(int table_id){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 1,
      .arg1 = (void *) &table_id,
    };
    int ecall_return;
    return_value ret = {
      .allocated_size = 0,
      .val = (void *) &ecall_return
    };
    make_hotcall(&ctx, ECALL_CCFE_C, &args, &ret);
    return ecall_return;
  #else
    int buffer_size;
    ecall_ccfe_c(global_eid,&buffer_size,table_id);
    return buffer_size;
  #endif
}
//24.2 Request
void SGX_ccfe_r(struct cls_rule **buf,int elem,int table_id){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 3,
      .arg1 = (void *) buf,
      .arg2 = (void *) &elem,
      .arg3 = (void *) &table_id,
    };
    make_hotcall(&ctx, ECALL_CCFE_R, &args, NULL);
  #else
    ecall_ccfe_r(global_eid,buf,elem,table_id);
  #endif
}

int SGX_collect_ofmonitor_util_c(int ofproto_n_tables,int table_id,const struct minimatch *match){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 1,
      .arg1 = (void *) &ofproto_n_tables,
      .arg2 = (void *) &table_id,
      .arg3 = (void *) match,
    };
    int ecall_return;
    return_value ret = {
      .allocated_size = 0,
      .val = (void *) &ecall_return
    };
    make_hotcall(&ctx, ECALL_COLLECT_OFMONITOR_UTIL_C, &args, &ret);
    return ecall_return;
  #else
    int count;
    ecall_collect_ofmonitor_util_c(global_eid,&count,ofproto_n_tables,table_id,match);
    return count;
  #endif
}

void SGX_collect_ofmonitor_util_r(int ofproto_n_tables,
                                  struct cls_rule **buf,
                                  int elem,
                                  int table_id,
                                  const struct minimatch *match){
 #ifdef HOTCALL
   argument_list args = {
     .n_args = 5,
     .arg1 = (void *) &ofproto_n_tables,
     .arg2 = (void *) buf,
     .arg3 = (void *) &elem,
     .arg4 = (void *) &table_id,
     .arg5 = (void *) match,
   };
   make_hotcall(&ctx, ECALL_COLLECT_OFMONITOR_UTIL_R, &args, NULL);
 #else
    ecall_collect_ofmonitor_util_r(global_eid,ofproto_n_tables,buf,elem,table_id,match);
 #endif
}


//25. One Part of Enable_eviction
void SGX_oftable_enable_eviction(int table_id,
                                 const struct mf_subfield *fields,
                                 size_t n_fields,
                                 uint32_t random_v){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 4,
      .arg1 = (void *) &table_id,
      .arg2 = (void *) fields,
      .arg3 = (void *) &n_fields,
      .arg4 = (void *) &random_v,
    };
    make_hotcall(&ctx, ECALL_OFTABLE_ENABLE_EVICTION, &args, NULL);
  #else
    ecall_oftable_enable_eviction(global_eid,table_id,fields,n_fields,random_v);
  #endif
}

//25.1
void SGX_oftable_disable_eviction(int table_id){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 1,
      .arg1 = (void *) &table_id,
    };
    make_hotcall(&ctx, ECALL_OFTABLE_DISABLE_EVICTION, &args, NULL);
  #else
    ecall_oftable_disable_eviction(global_eid,table_id);
  #endif
}

//26 oftable destroy
void SGX_ofproto_destroy(void){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 0,
    };
    make_hotcall(&ctx, ECALL_OFPROTO_DESTROY, &args, NULL);
  #else
    ecall_ofproto_destroy(global_eid);
  #endif
}

//27 Count total number of rules
unsigned int SGX_total_rules(void){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 0,
    };
    unsigned int ecall_return;
    return_value ret = {
      .allocated_size = 0,
      .val = (void *) &ecall_return
    };
    make_hotcall(&ctx, ECALL_TOTAL_RULES, &args, &ret);
    return ecall_return;
  #else
    unsigned int n_rules;
    ecall_total_rules(global_eid,&n_rules);
    return n_rules;
  #endif
}

//28 Copy the name of the table
void SGX_table_name(int table_id,char *buf,size_t len){
 #ifdef HOTCALL
     argument_list args = {
       .n_args = 3,
       .arg1 = (void *) &table_id,
       .arg2 = (void *) buf,
       .arg3 = (void *) &len,
     };
     make_hotcall(&ctx, ECALL_TABLE_NAME, &args, NULL);
 #else
    ecall_table_name(global_eid,table_id,buf,len);
 #endif
}

//29 loose_match
int SGX_cls_rule_is_loose_match(struct cls_rule *o_cls_rule,const struct minimatch *criteria){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 2,
        .arg1 = (void *) o_cls_rule,
        .arg2 = (void *) criteria,
      };
      int ecall_return;
      return_value ret = {
        .allocated_size = 0,
        .val = (void *) &ecall_return
      };
      make_hotcall(&ctx, ECALL_CLS_RULE_IS_LOOSE_MATCH, &args, &ret);
      return ecall_return;
  #else
    int result;
   	ecall_cls_rule_is_loose_match(global_eid,&result,o_cls_rule,criteria);
   	return result;
  #endif
}

//30. Dependencies for ofproto_flush__
int SGX_fet_ccfes_c(void){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 0,
      };
      int ecall_return;
      return_value ret = {
        .allocated_size = 0,
        .val = (void *) &ecall_return
      };
      make_hotcall(&ctx, ECALL_FET_CCFES_C, &args, &ret);
      return ecall_return;
  #else
    int count;
    ecall_fet_ccfes_c(global_eid,&count);
    return count;
  #endif
}

//30.1
void SGX_fet_ccfes_r(struct cls_rule **buf,int elem){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 2,
        .arg1 = (void *) buf,
        .arg2 = (void *) &elem,
      };
      make_hotcall(&ctx, ECALL_FET_CCFES_R, &args, NULL);
  #else
    ecall_fet_ccfes_r(global_eid,buf,elem);
  #endif
}

//31 Dependencies for ofproto_get_all_flows
int SGX_fet_ccfe_c(void){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 0,
      };
      int ecall_return;
      return_value ret = {
        .allocated_size = 0,
        .val = (void *) &ecall_return
      };
      make_hotcall(&ctx, ECALL_FET_CCFE_C, &args, &ret);
      return ecall_return;
  #else
    int count;
    ecall_fet_ccfe_c(global_eid,&count);
    return count;
  #endif
}

//31.2 REQUEST
void SGX_fet_ccfe_r(struct cls_rule **buf,int elem){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 2,
        .arg1 = (void *) buf,
        .arg2 = (void *) &elem,
      };
      make_hotcall(&ctx, ECALL_FEMT_CCFE_R, &args, NULL);
  #else
    ecall_fet_ccfe_r(global_eid,buf,elem);
  #endif
}

//33 Classifier_lookup
void SGX_cls_lookup(struct cls_rule **o_cls_rule,int table_id,const struct flow *flow,
		struct flow_wildcards *wc){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 4,
        .arg1 = (void *) o_cls_rule,
        .arg2 = (void *) &table_id,
        .arg3 = (void *) flow,
        .arg4 = (void *) wc,

      };
      make_hotcall(&ctx, ECALL_CLS_LOOKUP, &args, NULL);
  #else
    ecall_cls_lookup(global_eid,o_cls_rule,table_id,flow,wc);
  #endif
}

//34. CLS_RULE priority
unsigned int SGX_cls_rule_priority(struct cls_rule *o_cls_rule){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 1,
        .arg1 = (void *) o_cls_rule,
      };
      unsigned int ecall_return;
      return_value ret = {
        .allocated_size = 0,
        .val = (void *) &ecall_return
      };
      make_hotcall(&ctx, ECALL_CLS_RULE_PRIORITY, &args, &ret);
      return ecall_return;
  #else
    unsigned int priority;
    ecall_cls_rule_priority(global_eid,&priority,o_cls_rule);
    return priority;
  #endif
}

//Dependencies for destroy
int SGX_desfet_ccfes_c(void){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 0,
      };
      int ecall_return;
      return_value ret = {
        .allocated_size = 0,
        .val = (void *) &ecall_return
      };
      make_hotcall(&ctx, ECALL_DESFET_CCFES_C, &args, &ret);
      return ecall_return;
  #else
    int count;
    ecall_desfet_ccfes_c(global_eid,&count);
    return count;
  #endif
}

//2.
void SGX_desfet_ccfes_r(struct cls_rule **buf,int elem){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 2,
        .arg1 = (void *) buf,
        .arg2 = (void *) &elem,
      };
      make_hotcall(&ctx, ECALL_DESFET_CCFES_R, &args, NULL);
  #else
    ecall_desfet_ccfes_r(global_eid,buf,elem);
  #endif
}

//37. CLS_RULE_DEPENDENCIES
unsigned int SGX_cls_rule_format(const struct cls_rule *o_cls_rule,struct match *megamatch){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 2,
        .arg1 = (void *) o_cls_rule,
        .arg2 = (void *) megamatch,
      };
      unsigned int ecall_return;
      return_value ret = {
        .allocated_size = 0,
        .val = (void *) &ecall_return
      };
      make_hotcall(&ctx, ECALL_CLS_RULE_FORMAT, &args, &ret);
      return ecall_return;
  #else
    unsigned int priority;
    ecall_cls_rule_format(global_eid,&priority,o_cls_rule,megamatch);
    return priority;
  #endif
}

//38 miniflow_expand inside the enclave
//This functions copies from the enclave information into the struct flow.
void SGX_miniflow_expand(struct cls_rule *o_cls_rule,struct flow *flow){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 2,
        .arg1 = (void *) o_cls_rule,
        .arg2 = (void *) flow,
      };
      make_hotcall(&ctx, ECALL_MINIFLOW_EXPAND, &args, NULL);
  #else
    ecall_miniflow_expand(global_eid,o_cls_rule,flow);
  #endif
}

//39. Rule_calculate tag this needs to check the result and if not zero
//Calculate the tag_create deterministics
uint32_t SGX_rule_calculate_tag(struct cls_rule *o_cls_rule,const struct flow *flow,int table_id){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 3   ,
        .arg1 = (void *) o_cls_rule,
        .arg2 = (void *) flow,
        .arg3 = (void *) &table_id,
      };
      uint32_t ecall_return;
      return_value ret = {
        .allocated_size = 0,
        .val = (void *) &ecall_return
      };
      make_hotcall(&ctx, ECALL_RULE_CALCULATE_TAG, &args, &ret);
      return ecall_return;
  #else
    uint32_t hash;
    ecall_rule_calculate_tag(global_eid,&hash,o_cls_rule,flow,table_id);
    return hash;
  #endif
}

//This Functions are used for the table_dpif in ofproto_dpif {

//1.
void SGX_table_dpif_init(int n_tables){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 1,
      .arg1 = (void *) &n_tables,
    };
    make_hotcall(&ctx, ECALL_SGX_TABLE_DPIF, &args, NULL);
  #else
    ecall_SGX_table_dpif(global_eid,n_tables);
  #endif
}

//2.
int SGX_table_update_taggable(uint8_t table_id){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 1,
        .arg1 = (void *) &table_id,
      };
      int ecall_return;
      return_value ret = {
        .allocated_size = 0,
        .val = (void *) &ecall_return
      };
      make_hotcall(&ctx, ECALL_TABLE_UPDATE_TAGGABLE, &args, &ret);
      return ecall_return;
  #else
    int todo;
  	ecall_table_update_taggable(global_eid,&todo,table_id);
  	return todo;
  #endif
}

//3.
int SGX_is_sgx_other_table(int id){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 1,
        .arg1 = (void *) &id,
      };
      int ecall_return;
      return_value ret = {
        .allocated_size = 0,
        .val = (void *) &ecall_return
      };
      make_hotcall(&ctx, ECALL_IS_SGX_OTHER_TABLE, &args, &ret);
      return ecall_return;
  #else
    int result;
    ecall_is_sgx_other_table(global_eid,&result,id);
    return result;
  #endif
}

//4
uint32_t SGX_rule_calculate_tag_s(int id,const struct flow *flow,uint32_t secret){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 3,
        .arg1 = (void *) &id,
        .arg2 = (void *) flow,
        .arg3 = (void *) &secret,
      };
      uint32_t ecall_return;
      return_value ret = {
        .allocated_size = 0,
        .val = (void *) &ecall_return
      };
      make_hotcall(&ctx, ECALL_RULE_CALCULATE_TAG_S, &args, &ret);
      return ecall_return;
  #else
    uint32_t hash;
    ecall_rule_calculate_tag_s(global_eid,&hash,id,flow,secret);
    return hash;
  #endif
}

void sgx_oftable_check_hidden(void){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 0,
      };
      make_hotcall(&ctx, ECALL_HIDDEN_TABLES_CHECK, &args, NULL);
  #else
    ecall_hidden_tables_check(global_eid);
  #endif
}

void SGX_oftable_set_name(int table_id, char *name){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 2,
        .arg1 = (void *) &table_id,
        .arg2 = (void *) name,
      };
      make_hotcall(&ctx, ECALL_OFTABLE_SET_NAME, &args, NULL);
  #else
    ecall_oftable_set_name(global_eid,table_id, name);
  #endif
}

//These functions are going to be used by ofopgroup_complete
uint16_t SGX_minimask_get_vid_mask(struct cls_rule *o_cls_rule){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 1,
        .arg1 = (void *) o_cls_rule,
      };
      uint16_t ecall_return;
      return_value ret = {
        .allocated_size = 0,
        .val = (void *) &ecall_return
      };
      make_hotcall(&ctx, ECALL_MINIMASK_GET_VID_MASK, &args, &ret);
      return ecall_return;
  #else
    uint16_t result;
    ecall_minimask_get_vid_mask(global_eid,&result,o_cls_rule);
    return result;
  #endif
}

uint16_t SGX_miniflow_get_vid(struct cls_rule *o_cls_rule){
   #ifdef HOTCALL
       argument_list args = {
         .n_args = 1,
         .arg1 = (void *) o_cls_rule,
       };
       uint16_t ecall_return;
       return_value ret = {
         .allocated_size = 0,
         .val = (void *) &ecall_return
       };
       make_hotcall(&ctx, ECALL_MINIFLOW_GET_VID, &args, &ret);
       return ecall_return;
   #else
    uint16_t result;
    ecall_miniflow_get_vid(global_eid,&result,o_cls_rule);
    return result;
   #endif
}

//These functions are depencencies for ofproto_get_vlan_usage
//1. Count
int SGX_ofproto_get_vlan_usage_c(void){
  #ifdef HOTCALL
    argument_list args = {
      .n_args = 0,
    };
    int ecall_return;
    return_value ret = {
      .allocated_size = 0,
      .val = (void *) &ecall_return
    };
    make_hotcall(&ctx, ECALL_OFPROTO_GET_VLAN_C, &args, &ret);
    return ecall_return;
  #else
    int count;
  	ecall_ofproto_get_vlan_c(global_eid,&count);
  	return count;
  #endif
}

//2. Allocate
void SGX_ofproto_get_vlan_usage__r(uint16_t *buf,int elem){
  #ifdef HOTCALL
      argument_list args = {
        .n_args = 2,
        .arg1 = (void *) buf,
        .arg2 = (void *) &elem,
      };
      make_hotcall(&ctx, ECALL_OFPROTO_GET_VLAN_R, &args, NULL);
  #else
    ecall_ofproto_get_vlan_r(global_eid, buf, elem);
  #endif
}
