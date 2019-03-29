#ifndef _MYENCLAVE_H_
#define _MYENCLAVE_H_

#include <stdlib.h>
#include <assert.h>


extern struct oftable * SGX_oftables;
extern struct sgx_cls_table * SGX_hmap_table;
struct SGX_table_dpif * SGX_table_dpif;
extern int SGX_n_tables;

/* Assigns TABLE to each oftable, in turn, in OFPROTO.
 *
 * All parameters are evaluated multiple times. */
#define OFPROTO_FOR_EACH_TABLE(TABLE, SGX_TABLES)              \
    for ((TABLE) = SGX_TABLES;                       \
         (TABLE) < &SGX_TABLES[SGX_n_tables]; \
         (TABLE)++)


#if defined(__cplusplus)
extern "C" {
#endif


void printf(const char *fmt, ...);

#if defined(__cplusplus)
}
#endif

#endif /* !_MYENCLAVE_H_ */
