#ifndef _SGX_COMMON_H
#define _SGX_COMMON_H

#include <sgx_spinlock.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sgx_thread.h>

#define ECALL_MYENCLAVE_SAMPLE 0
#define ECALL_OFPROTO_INIT_TABLES 1
#define ECALL_READONLY_SET 2
#define ECALL_ISTABLE_READONLY 3
#define ECALL_CLS_RULE_INIT 4
#define ECALL_CR_RULE_OVERLAPS 5
#define ECALL_CLS_RULE_DESTROY 6
#define ECALL_CLS_RULE_HASH 7
#define ECALL_CLS_RULE_EQUAL 8
#define ECALL_CLASSIFIER_REPLACE 9
#define ECALL_RULE_GET_FLAGS 10
#define ECALL_CLS_COUNT 11
#define ECALL_EVICTION_FIELDS_ENABLE 12
#define ECALL_EVG_GROUP_RESIZE 13
#define ECALL_EVG_ADD_RULE 14
#define ECALL_EVG_REMOVE_RULE 15
#define ECALL_CLS_REMOVE 16
#define ECALL_CHOOSE_RULE_TO_EVICT 17
#define ECALL_TABLE_MFLOWS 18
#define ECALL_CHOOSE_RULE_TO_EVICT_P 19
#define ECALL_MINIMATCH_EXPAND 20
#define ECALL_CR_PRIORITY 21
#define ECALL_CLS_FIND_MATCH_EXACTLY 22
#define ECALL_FEMT_CCFE_C 23
#define ECALL_FEMT_CCFE_R 24
#define ECALL_FEMT_C 25
#define ECALL_FEMT_R 26
#define ECALL_OFTABLE_ENABLE_EVICTION 27
#define ECALL_OFTABLE_DISABLE_EVICTION 28
#define ECALL_CCFE_C 29
#define ECALL_CCFE_R 30
#define ECALL_TABLE_MFLOWS_SET 31
#define ECALL_OFPROTO_DESTROY 32
#define ECALL_TOTAL_RULES 33
#define ECALL_TABLE_NAME 34
#define ECALL_COLLECT_OFMONITOR_UTIL_C 35
#define ECALL_COLLECT_OFMONITOR_UTIL_R 36
#define ECALL_CLS_RULE_IS_LOOSE_MATCH 37
#define ECALL_FET_CCFES_C 38
#define ECALL_FET_CCFES_R 39
#define ECALL_FET_CCFE_C 40
#define ECALL_FET_CCFE_R 41
#define ECALL_CLS_LOOKUP 42
#define ECALL_CLS_RULE_PRIORITY 43
#define ECALL_DESFET_CCFES_C 44
#define ECALL_DESFET_CCFES_R 45
#define ECALL_CLS_RULE_FORMAT 46
#define ECALL_MINIFLOW_EXPAND 47
#define ECALL_RULE_CALCULATE_TAG 48
#define ECALL_SGX_TABLE_DPIF 49
#define ECALL_TABLE_UPDATE_TAGGABLE 50
#define ECALL_IS_SGX_OTHER_TABLE 51
#define ECALL_RULE_CALCULATE_TAG_S 52
#define ECALL_HIDDEN_TABLES_CHECK 53
#define ECALL_OFTABLE_SET_NAME 54
#define ECALL_MINIMASK_GET_VID_MASK 55
#define ECALL_MINIFLOW_GET_VID 56
#define ECALL_OFPROTO_GET_VLAN_C 57
#define ECALL_OFPROTO_GET_VLAN_R 58


typedef struct {
  int n_args;
  void *arg1;
  void *arg2;
  void *arg3;
  void *arg4;
  void *arg5;
  void *arg6;

} argument_list;


typedef struct {
  size_t allocated_size;
  void *val;
} return_value;

typedef struct {
  sgx_thread_mutex_t mutex;
  sgx_spinlock_t spinlock;
  sgx_thread_cond_t cond;
  bool run;
  bool running_function;
  bool is_done;
  bool sleeping;
  int timeout_counter;
  int function;
  argument_list *args;
  return_value *ret;
} async_ecall;

#endif
