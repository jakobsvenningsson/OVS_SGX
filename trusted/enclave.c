#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include "enclave.h"
#include "enclave_t.h"  /* print_string */
#include <stdbool.h>
#include "classifier.h"
#include "ofproto-provider.h"
#include "enclave-utils.h"
#include "helpers.h"
#include "call-table.h"
#include <sgx_spinlock.h>

#ifdef TIMEOUT
#define INIT_TIMER_VALUE 9999999;
static unsigned int timeout_counter = INIT_TIMER_VALUE;
#endif


struct sgx_cls_table * SGX_hmap_table;
struct oftable * SGX_oftables;
struct SGX_table_dpif * SGX_table_dpif;
int SGX_n_tables;

/* Open vSwitch Trusted function definitions */
static void
oftable_init(struct oftable *table)
{
    memset(table, 0, sizeof *table);
    classifier_init(&table->cls);
    table->max_flows = UINT_MAX;
}

void
ecall_ofproto_init_tables(int n_tables)
{
	struct oftable *table;
	SGX_n_tables=n_tables;
	SGX_oftables = xmalloc(n_tables * sizeof(struct oftable));
    OFPROTO_FOR_EACH_TABLE (table, SGX_oftables) {
        oftable_init(table);
    }
    //This is set in ofproto_dpif.c
    //Initialization of the hmap containing SGX_rules
    printf("Initialization of the hmap tables\n");
    sgx_table_cls_init();

}

void ecall_readonly_set(int table_id){
	SGX_oftables[TBL_INTERNAL].flags=OFTABLE_HIDDEN | OFTABLE_READONLY;
}

int ecall_istable_readonly(uint8_t table_id){
	return SGX_oftables[table_id].flags & OFTABLE_READONLY;
}

void ecall_cls_rule_init(struct cls_rule * o_cls_rule,
		const struct match * match , unsigned int priority){

	//We proceed to insert the cls_rule to the hash_map
	struct sgx_cls_rule *sgx_cls_rule= node_insert(hash_pointer(o_cls_rule,0));

	//Save the pointer into the sgx_cls_rule in o_cls_rule
	sgx_cls_rule->o_cls_rule=o_cls_rule;

	//Initialization of the cls_rule (trusted)
	cls_rule_init(&sgx_cls_rule->cls_rule,match,priority);

	//Set the eviction set of the rule to default=TRUE
	sgx_cls_rule->evictable=true;


}

void ecall_cls_rule_init_i(struct cls_rule * cls_rule,
		const struct match * match , unsigned int priority){
	cls_rule_init(cls_rule,match,priority);
}


//5. Classifier_rule_overlaps
int ecall_cr_rule_overlaps(int table_id,struct cls_rule * out){
	//1. Look for the corresponding cls_rule in the enclave to do so we use
	//the macro container_of

	struct sgx_cls_rule *sgx_cls_rule=node_search(out);

	//2. I need to retrieve the cls_rule sgx_cls_rule->cls_rule....
	struct cls_rule *cls_rule= &sgx_cls_rule->cls_rule;

	//3. Verify with the classifier...
	const struct classifier *cls=&SGX_oftables[table_id].cls;
	const struct cls_rule *target=cls_rule;

	if (classifier_rule_overlaps(cls,target)){
		return 100;
	}
	return 0;
}

//6. cls_rule_destroy

void ecall_cls_rule_destroy(struct cls_rule *out){
	//1. need to recover the cls_rule in the enclave.
	struct sgx_cls_rule * sgx_cls_rule=node_search(out);
	//2. we get the cls_rule
	struct cls_rule *cls_rule= &sgx_cls_rule->cls_rule;
	cls_rule_destroy(cls_rule);
	//3. free the sgx_cls_rule
	node_delete(sgx_cls_rule->o_cls_rule);
	//free(sgx_cls_rule);
	sgx_cls_rule=NULL;
}

//7. cls_rule_hash
uint32_t ecall_cls_rule_hash(const struct cls_rule * o_cls_rule, uint32_t basis){
	//1. need to recover the cls_rule in the enclave.
	struct sgx_cls_rule * sgx_cls_rule=node_search(o_cls_rule);
	//2. we get the cls_rule

	struct cls_rule *cls_rule= &sgx_cls_rule->cls_rule;
	return cls_rule_hash(cls_rule,basis);
}

//8. cls_rule_equal
int ecall_cls_rule_equal(const struct cls_rule *out_a, const struct cls_rule *out_b){
	struct sgx_cls_rule * sgx_cls_rule_a=node_search(out_a);
	struct sgx_cls_rule * sgx_cls_rule_b=node_search(out_b);
	const struct cls_rule *a = &sgx_cls_rule_a->cls_rule;
	const struct cls_rule *b = &sgx_cls_rule_b->cls_rule;
	if(cls_rule_equal(a,b)){
		return 100;
	}
	return 0;
}

//9. classifier_replace
void ecall_classifier_replace(int table_id,struct cls_rule* o_cls_rule,struct cls_rule ** cls_rule_rtrn){

	struct sgx_cls_rule * sgx_cls_rule=node_search(o_cls_rule);

	struct cls_rule * cls_rule=classifier_replace(&SGX_oftables[table_id].cls,&sgx_cls_rule->cls_rule);

	//cls_rule will return NULL or a pointer to a cls_rule
	if(cls_rule){
		struct sgx_cls_rule *sgx_cls_rule_r=CONTAINER_OF(cls_rule,struct sgx_cls_rule,cls_rule);
		*cls_rule_rtrn=sgx_cls_rule_r->o_cls_rule;
	}else{
		*cls_rule_rtrn=NULL;
	}

}

//10. rule_get_flags
enum oftable_flags ecall_rule_get_flags(int table_id){
	return SGX_oftables[table_id].flags;
}

//11. Classifier_count
int ecall_cls_count(int table_id){
	return classifier_count(&SGX_oftables[table_id].cls);
}

//12. Table has eviction_fields enable?
int ecall_eviction_fields_enable(int table_id){
	if(SGX_oftables[table_id].eviction_fields){
		return 100;
	}
	return 0;
}

//13 eviction group find
static struct eviction_group *
ecall_evg_find(int table_id,uint32_t id,uint32_t priority){
	struct eviction_group *evg;
	HMAP_FOR_EACH_WITH_HASH (evg, id_node,id,&SGX_oftables[table_id].eviction_groups_by_id) {
	        return evg;
	    }
	evg = xmalloc(sizeof *evg);
	hmap_insert(&SGX_oftables[table_id].eviction_groups_by_id, &evg->id_node, id);
	heap_insert(&SGX_oftables[table_id].eviction_groups_by_size, &evg->size_node,priority);
	heap_init_ovs(&evg->rules);
	return evg;
}

//14

static uint32_t
eviction_group_hash_rule(int table_id,struct cls_rule *cls_rule){
    const struct mf_subfield *sf;
    struct flow flow;
    uint32_t hash;
    hash=SGX_oftables[table_id].eviction_group_id_basis;
    miniflow_expand(&cls_rule->match.flow, &flow);
    for (sf =SGX_oftables[table_id].eviction_fields;
             sf< &SGX_oftables[table_id].eviction_fields[SGX_oftables[table_id].n_eviction_fields];
             sf++)
    {
    	if (mf_are_prereqs_ok(sf->field, &flow)) {
    		union mf_value value;
    		mf_get_value(sf->field, &flow, &value);
    		if (sf->ofs) {
    		    bitwise_zero(&value, sf->field->n_bytes, 0, sf->ofs);
    		}
    		if (sf->ofs + sf->n_bits < sf->field->n_bytes * 8) {
    			unsigned int start = sf->ofs + sf->n_bits;
    			bitwise_zero(&value, sf->field->n_bytes, start,
    			             sf->field->n_bytes * 8 - start);
    		}
    		hash = hash_bytes(&value, sf->field->n_bytes, hash);

    	}else {
    		hash=hash_int(hash,0);
    	}
    }
    return hash;
}

//15. eviction_grpu_add and eviction group find

size_t
ecall_evg_add_rule(int table_id,struct cls_rule *o_cls_rule,uint32_t priority,uint32_t rule_evict_prioriy,struct heap_node rule_evg_node){
	struct sgx_cls_rule * sgx_cls_rule=node_search(o_cls_rule);
	struct eviction_group *evg;
	evg=ecall_evg_find(table_id,eviction_group_hash_rule(table_id,&sgx_cls_rule->cls_rule),priority);
	sgx_cls_rule->evict_group=evg;
	sgx_cls_rule->rule_evg_node=rule_evg_node;
	heap_insert(&evg->rules, &sgx_cls_rule->rule_evg_node,rule_evict_prioriy);
	return heap_count(&evg->rules);

}

//16
void ecall_evg_group_resize(int table_id,struct cls_rule *o_cls_rule,size_t priority){
	struct sgx_cls_rule * sgx_cls_rule=node_search(o_cls_rule);
	heap_change(&SGX_oftables[table_id].eviction_groups_by_size,&sgx_cls_rule->evict_group->size_node,priority);
}

/* 18 Eviction_group_destroy: Destroys 'evg' and eviction_group within 'table
removes all the rules, if any, from evg. it does not destroy the rules just removes them from the eviction group.

*/

void ecall_evg_destroy(int table_id, struct eviction_group *evg){
	while (!heap_is_empty(&evg->rules)) {
		struct sgx_cls_rule * sgx_cls_rule=node_search_evict(evg);
		sgx_cls_rule->evict_group=NULL;
	 }
	hmap_remove(&SGX_oftables[table_id].eviction_groups_by_id, &evg->id_node);
	heap_remove(&SGX_oftables[table_id].eviction_groups_by_size, &evg->size_node);
	heap_destroy(&evg->rules);
	free(evg);
}


//17. Eviction_grouP_remove_rule: Delete the eviction group of a rule if it is not NULL

int ecall_evg_remove_rule(int table_id,struct cls_rule *o_cls_rule){
	int evg_resized=-1; //no need resized
	struct sgx_cls_rule * sgx_cls_rule=node_search(o_cls_rule);
	if(sgx_cls_rule->evict_group){
		struct eviction_group *evg=sgx_cls_rule->evict_group;
		sgx_cls_rule->evict_group=NULL;
		heap_remove(&evg->rules,&sgx_cls_rule->rule_evg_node);
		if (heap_is_empty(&evg->rules)){
			ecall_evg_destroy(table_id, evg);
		}else{
			evg_resized=heap_count(&evg->rules);
			return evg_resized; // means requires evg_group_resized....
		}
	}
	return evg_resized;
}


//18. Classifier remove: removes a cls_rule from the classifier
void ecall_cls_remove(int table_id,struct cls_rule *o_cls_rule){
	struct sgx_cls_rule * sgx_cls_rule=node_search(o_cls_rule);
	classifier_remove(&SGX_oftables[table_id].cls, &sgx_cls_rule->cls_rule);
}
//////////////////////////////////////////////////////////////////////


//19 choose and return a rule to evict from table
void ecall_choose_rule_to_evict(int table_id,struct cls_rule *o_cls_rule){
	struct eviction_group *evg;
	if (!SGX_oftables[table_id].eviction_fields) {
	        o_cls_rule= NULL;
	}
	HEAP_FOR_EACH (evg, size_node, &SGX_oftables[table_id].eviction_groups_by_size) {
		struct sgx_cls_rule * sgx_cls_rule;
		HEAP_FOR_EACH (sgx_cls_rule, rule_evg_node, &evg->rules){
			if(sgx_cls_rule->evictable){
				o_cls_rule=sgx_cls_rule->o_cls_rule;
			}
		}
	}
	o_cls_rule= NULL;
}

//20. choose and return a rule to evict from table, without including the rule itself
void ecall_choose_rule_to_evict_p(int table_id,struct cls_rule *o_cls_rule){
	struct sgx_cls_rule * sgx_cls_rule=node_search(o_cls_rule);
	bool was_evictable;
	was_evictable = sgx_cls_rule->evictable;
	sgx_cls_rule->evictable=false;
	ecall_choose_rule_to_evict(table_id,o_cls_rule);
	sgx_cls_rule->evictable=was_evictable;

}


//21 returns the table max_flows
unsigned int ecall_table_mflows(int table_id){
	return SGX_oftables[table_id].max_flows;
}

//22. Set table max_flows
//21 returns the table max_flows
void ecall_table_mflows_set(int table_id,unsigned int value){
	SGX_oftables[table_id].max_flows=value;
}


//22. Minimatch_expand inside the enclave
void ecall_minimatch_expand(struct cls_rule *o_cls_rule,struct match *dst){
	struct sgx_cls_rule * sgx_cls_rule=node_search(o_cls_rule);
	minimatch_expand(&sgx_cls_rule->cls_rule.match,dst);
}

//23. cls_rule priority
unsigned int ecall_cr_priority(struct cls_rule *o_cls_rule){
	struct sgx_cls_rule * sgx_cls_rule=node_search(o_cls_rule);
	return sgx_cls_rule->cls_rule.priority;

}

/* Finds and returns a rule in 'cls' with priority 'priority' and exactly the
 * same matching criteria as 'target'.  Returns a null pointer if 'cls' doesn't
 * contain an exact match. */
//24 classifier_find_match_exactly
void ecall_cls_find_match_exactly(int table_id,
                              const struct match *target,
                              unsigned int priority,struct cls_rule ** o_cls_rule){



	struct cls_rule * cls_rule=classifier_find_match_exactly(&SGX_oftables[table_id].cls,
			target,priority);

	//Since this function returns NULL if no match entry, we have to take care of it
	if(cls_rule){

		struct sgx_cls_rule * sgx_cls_rule=CONTAINER_OF(cls_rule,struct sgx_cls_rule,cls_rule);

		*o_cls_rule=sgx_cls_rule->o_cls_rule;
	}

	else{
		*o_cls_rule=NULL;
	}
}


//25. Next Visible table
static struct oftable *
next_visible_table(int ofproto_n_tables, uint8_t table_id){

	struct oftable *table;

	for (table = &SGX_oftables[table_id];
	         table < &SGX_oftables[ofproto_n_tables];
	         table++) {
	        if (!(table->flags & OFTABLE_HIDDEN)) {
	            return table;
	        }
	    }

	    return NULL;
}

//26. First _matching_table
static struct oftable *
first_matching_table(int ofproto_n_tables, uint8_t table_id)
{
    if (table_id == 0xff) {
        return next_visible_table(ofproto_n_tables, 0);
    } else if (table_id < ofproto_n_tables) {
        return &SGX_oftables[table_id];
    } else {
        return NULL;
    }
}

//27. next matching table
static struct oftable *
next_matching_table(int ofproto_n_tables,
                    const struct oftable *table, uint8_t table_id)
{
    return (table_id == 0xff
            ? next_visible_table(ofproto_n_tables, (table - SGX_oftables) + 1)
            : NULL);
}

#define FOR_EACH_MATCHING_TABLE(TABLE, TABLE_ID, OFPROTO)         \
    for ((TABLE) = first_matching_table(OFPROTO, TABLE_ID);       \
         (TABLE) != NULL;                                         \
         (TABLE) = next_matching_table(OFPROTO, TABLE, TABLE_ID))


/////////Special Functions with loops //////
int ecall_femt_ccfe_c(int ofproto_n_tables,uint8_t table_id,const struct match *match){
	struct oftable *table;
	struct cls_rule cr;
	ecall_cls_rule_init_i(&cr,match , 0);
	int count=0;
	FOR_EACH_MATCHING_TABLE (table, table_id, ofproto_n_tables){
		struct cls_cursor cursor;
		struct sgx_cls_rule *rule;

		cls_cursor_init(&cursor, &table->cls, &cr);
		CLS_CURSOR_FOR_EACH (rule, cls_rule, &cursor){
			count++;
		}
	}
	cls_rule_destroy(&cr);
	return count;
}

void ecall_femt_ccfe_r(int ofproto_n_tables,struct cls_rule **buf,int elem,uint8_t table_id,const struct match *match){
	struct oftable *table;
	struct cls_rule cr;
	ecall_cls_rule_init_i(&cr,match , 0);
	int p=0;
	FOR_EACH_MATCHING_TABLE (table, table_id, ofproto_n_tables){
		struct cls_cursor cursor;
		struct sgx_cls_rule *rule;

		cls_cursor_init(&cursor, &table->cls, &cr);
		CLS_CURSOR_FOR_EACH (rule, cls_rule, &cursor){
			if(p>elem){
				return;
			}
			//struct sgx_cls_rule * sgx_cls_rule=CONTAINER_OF(rule,struct sgx_cls_rule,cls_rule);
			//buf[p]=sgx_cls_rule->o_cls_rule;
			buf[p]=rule->o_cls_rule;
			p++;
		}
	}
	cls_rule_destroy(&cr);

}

//39. Dependecy in ofproto_collect_ofmonitor_refresh_rules.
int ecall_collect_ofmonitor_util_c(int ofproto_n_tables,int table_id,const struct minimatch *match){
	struct cls_rule target;
	const struct oftable *table;
	int count=0;
	cls_rule_init_from_minimatch(&target,match,0);
	FOR_EACH_MATCHING_TABLE (table, table_id, ofproto_n_tables){
		struct cls_cursor cursor;
		struct sgx_cls_rule *rule;
		cls_cursor_init(&cursor, &table->cls, &target);
		CLS_CURSOR_FOR_EACH (rule, cls_rule, &cursor) {
			count++;
		}

	}
	minimatch_destroy(&target.match);
	return count;
}

void ecall_collect_ofmonitor_util_r(int ofproto_n_tables,struct cls_rule **buf,int elem,int table_id,const struct minimatch *match){
	struct cls_rule target;
	const struct oftable *table;
	int p=0;
	cls_rule_init_from_minimatch(&target,match,0);
	FOR_EACH_MATCHING_TABLE (table, table_id, ofproto_n_tables){
		struct cls_cursor cursor;
		struct sgx_cls_rule *rule;
		cls_cursor_init(&cursor, &table->cls, &target);
		CLS_CURSOR_FOR_EACH (rule, cls_rule, &cursor) {
			if(p>elem){
				//overflow: this needs to be handle.
				return;
			}
			//struct sgx_cls_rule * sgx_cls_rule=CONTAINER_OF(rule,struct sgx_cls_rule,cls_rule);
			//buf[p]=sgx_cls_rule->o_cls_rule;
			buf[p]=rule->o_cls_rule;
			p++;
		}

	}
	minimatch_destroy(&target.match); //to diassociate the target because if its a temp cls_rule

}

//Dependencies for ofproto_flush___

//50.1 Need to know the size of the buffer to allocate
int ecall_fet_ccfes_c(void){
	int i;
	int count=0;
	for(i=0;i<SGX_n_tables;i++){
		struct sgx_cls_rule *rule,*next_rule;
		struct cls_cursor cursor;
		if(SGX_oftables[i].flags & OFTABLE_HIDDEN){
			continue;
		}

		cls_cursor_init(&cursor,&SGX_oftables[i].cls,NULL);
		CLS_CURSOR_FOR_EACH_SAFE(rule,next_rule,cls_rule,&cursor){
			count++;
		}
	}
	return count;
}

//50.2
void ecall_fet_ccfes_r(struct cls_rule **buf,int elem){
	int p=0;
	int i;
	for(i=0;i<SGX_n_tables;i++){
			struct sgx_cls_rule *rule,*next_rule;
			struct cls_cursor cursor;
			if(SGX_oftables[i].flags & OFTABLE_HIDDEN){
				continue;
			}

			cls_cursor_init(&cursor,&SGX_oftables[i].cls,NULL);
			CLS_CURSOR_FOR_EACH_SAFE(rule,next_rule,cls_rule,&cursor){
				if(p>elem){
						//overflow: this needs to be handle.
						return;
					}
					//struct sgx_cls_rule * sgx_cls_rule=CONTAINER_OF(rule,struct sgx_cls_rule,cls_rule);
					//buf[p]=sgx_cls_rule->o_cls_rule;
					buf[p]=rule->o_cls_rule;
					p++;
			}
		}
}

//Dependencies for ofproto_get_all_flows
//51. COUNT
int ecall_fet_ccfe_c(void){
	int i;
	int count=0;
	for(i=0;i<SGX_n_tables;i++){
		struct sgx_cls_rule *rule;
		struct cls_cursor cursor;
		cls_cursor_init(&cursor,&SGX_oftables[i].cls,NULL);
		CLS_CURSOR_FOR_EACH(rule,cls_rule,&cursor){
			count++;
		}
	}
	return count;
}

//51.2 REQUEST
void ecall_fet_ccfe_r(struct cls_rule **buf,int elem){
	int p=0;
	int i;
	for(i=0;i<SGX_n_tables;i++){
			struct sgx_cls_rule *rule;
			struct cls_cursor cursor;
			cls_cursor_init(&cursor,&SGX_oftables[i].cls,NULL);
			CLS_CURSOR_FOR_EACH(rule,cls_rule,&cursor){
				if(p>elem){
						//overflow: this needs to be handle.
						return;
					}
					//struct sgx_cls_rule * sgx_cls_rule=CONTAINER_OF(rule,struct sgx_cls_rule,cls_rule);
					//buf[p]=sgx_cls_rule->o_cls_rule;
					buf[p]=rule->o_cls_rule;
					p++;
			}
		}
}

int ecall_femt_c(int ofproto_n_tables,uint8_t table_id,const struct match *match,unsigned int priority){
	struct oftable *table;
	struct cls_rule cr;
	ecall_cls_rule_init_i(&cr,match ,priority);
	int count=0;
	FOR_EACH_MATCHING_TABLE (table, table_id, ofproto_n_tables){

		if(classifier_find_rule_exactly(&table->cls,&cr)){
			count++;
		}
	}
	cls_rule_destroy(&cr);
	return count;
}

void ecall_femt_r(int ofproto_n_tables,struct cls_rule **buf,int elem,uint8_t table_id,const struct match *match,unsigned int priority)
{
	struct oftable *table;
	struct cls_rule cr;
	ecall_cls_rule_init_i(&cr,match ,priority);
	int p=0;
	FOR_EACH_MATCHING_TABLE (table, table_id, ofproto_n_tables){
		struct cls_rule * cls_rule=classifier_find_rule_exactly(&table->cls,&cr);
		if(cls_rule){
			if(p>elem){
				//overflow: this needs to be handle.
				return;
			}
			struct sgx_cls_rule * sgx_cls_rule=CONTAINER_OF(cls_rule,struct sgx_cls_rule,cls_rule);
			buf[p]=sgx_cls_rule->o_cls_rule;
			p++;
		}
	}
	cls_rule_destroy(&cr);
}

int ecall_ccfe_c(int table_id){
	int count=0;
	struct cls_cursor cursor;
	struct sgx_cls_rule * rule;
	cls_cursor_init(&cursor,&SGX_oftables[table_id].cls, NULL);
	CLS_CURSOR_FOR_EACH (rule, cls_rule, &cursor) {
		count++;
	}
	return count;
}

void ecall_ccfe_r(struct cls_rule **buf,int elem,int table_id){
	struct cls_cursor cursor;
	struct sgx_cls_rule * rule;
	int p=0;
	cls_cursor_init(&cursor,&SGX_oftables[table_id].cls, NULL);
	CLS_CURSOR_FOR_EACH (rule, cls_rule, &cursor) {
		if(rule){
			if(p>elem){
				//overflow: this needs to be handle.
			    return;
			}
			//struct sgx_cls_rule * sgx_cls_rule=CONTAINER_OF(rule,struct sgx_cls_rule,cls_rule);
		    //buf[p]=sgx_cls_rule->o_cls_rule;
			buf[p]=rule->o_cls_rule;
			p++;
		}
	}
}




//32  oftable_set_name
void
ecall_oftable_set_name(int table_id, char *name)
{
    if (name && name[0]) {
        int len = strnlen(name, OFP_MAX_TABLE_NAME_LEN);
        if (!SGX_oftables[table_id].name || strncmp(name, SGX_oftables[table_id].name, len)) {
            free(SGX_oftables[table_id].name);
            SGX_oftables[table_id].name = xmemdup0(name, len);
        }
    } else {
        free(SGX_oftables[table_id].name);
        SGX_oftables[table_id].name = NULL;
    }
}

//33. oftable_disable_eviction
void
ecall_oftable_disable_eviction(int table_id)
{
    if (SGX_oftables[table_id].eviction_fields) {
        struct eviction_group *evg, *next;

        HMAP_FOR_EACH_SAFE (evg, next, id_node,
        					&SGX_oftables[table_id].eviction_groups_by_id)
        {
        	ecall_evg_destroy(table_id, evg);
        }
        hmap_destroy(&SGX_oftables[table_id].eviction_groups_by_id);
        heap_destroy(&SGX_oftables[table_id].eviction_groups_by_size);

        free(SGX_oftables[table_id].eviction_fields);
        SGX_oftables[table_id].eviction_fields = NULL;
        SGX_oftables[table_id].n_eviction_fields = 0;
    }
}

void ecall_oftable_enable_eviction(int table_id,const struct mf_subfield *fields,size_t n_fields,uint32_t random_v)
{
	if(SGX_oftables[table_id].eviction_fields
		&& n_fields == SGX_oftables[table_id].n_eviction_fields
		&& (!n_fields
				|| !memcmp(fields, SGX_oftables[table_id].eviction_fields,
						n_fields * sizeof *fields))){
							return;
	}

	ecall_oftable_disable_eviction(table_id);
	SGX_oftables[table_id].n_eviction_fields = n_fields;
	SGX_oftables[table_id].eviction_fields=xmemdup(fields, n_fields * sizeof *fields);
	SGX_oftables[table_id].eviction_group_id_basis=random_v;

	hmap_init(&SGX_oftables[table_id].eviction_groups_by_id);
	heap_init(&SGX_oftables[table_id].eviction_groups_by_size);

}

void ecall_oftable_destroy(int table_id){
	ovs_assert(classifier_is_empty(&SGX_oftables[table_id].cls));
	ecall_oftable_disable_eviction(table_id);
	classifier_destroy(&SGX_oftables[table_id].cls);
	free(SGX_oftables[table_id].name);
}

void ecall_ofproto_destroy(){
	int i;
	for(i=0;i<SGX_n_tables;i++){
		ecall_oftable_destroy(i);
	}
	free(SGX_oftables);
}

//37 count total number of rules
unsigned int ecall_total_rules(void){
	int i;
	unsigned int n_rules;
	n_rules =0;
	for(i=0;i<SGX_n_tables;i++){
		n_rules+=classifier_count(&SGX_oftables[i].cls);
	}
	return n_rules;
}

//38 Table name
void ecall_table_name(int table_id,char *buf,size_t len){
	//I set the value manually to 100;
if(SGX_oftables[table_id].name){
	if (len>strlen(SGX_oftables[table_id].name)){
		memcpy(buf,SGX_oftables[table_id].name,strlen(SGX_oftables[table_id].name)+1);
	}else{
		memcpy(buf,SGX_oftables[table_id].name,len);
	}
 }else{
	 memset(buf,0,len);
 }
}

//another



int ecall_cls_rule_is_loose_match(struct cls_rule *o_cls_rule,const struct minimatch *criteria){
	struct sgx_cls_rule * sgx_cls_rule=node_search(o_cls_rule);
	if(cls_rule_is_loose_match(&sgx_cls_rule->cls_rule,criteria)){
			return 100;
		}

		return 0;
}







//////////////////////////////////////////////////

///FUNCTION FOR OFPROTO_DPIF.c

//1. Classifier_lookup
void ecall_cls_lookup(struct cls_rule **o_cls_rule,int table_id,const struct flow *flow,
		struct flow_wildcards *wc){
	struct cls_rule *cls_rule;
	cls_rule=classifier_lookup(&SGX_oftables[table_id].cls,flow,wc);
	if (cls_rule){
		//Need to retrieve the sgx_cls_rule and return the pointer
		//to untrusted memory
		struct sgx_cls_rule *sgx_cls_rule=CONTAINER_OF(cls_rule,struct sgx_cls_rule,cls_rule);
		*o_cls_rule=sgx_cls_rule->o_cls_rule;
	}else{
		*o_cls_rule=NULL;
	}

}

//2. cls_rule priority
unsigned int ecall_cls_rule_priority(struct cls_rule *o_cls_rule){
	//we need to find this rule using this pointer
	struct sgx_cls_rule *sgx_cls_rule;
	sgx_cls_rule =node_search(o_cls_rule);
	return sgx_cls_rule->cls_rule.priority;

}

//Dependencies for destruct
int ecall_desfet_ccfes_c(void){
	int i;
	int count=0;
	for(i=0;i<SGX_n_tables;i++){
		struct sgx_cls_rule *rule,*next_rule;
		struct cls_cursor cursor;

		cls_cursor_init(&cursor,&SGX_oftables[i].cls,NULL);
		CLS_CURSOR_FOR_EACH_SAFE(rule,next_rule,cls_rule,&cursor){
			count++;
		}
	}
	return count;
}

//50.2
void ecall_desfet_ccfes_r(struct cls_rule **buf,int elem){
	int p=0;
	int i;
	for(i=0;i<SGX_n_tables;i++){
			struct sgx_cls_rule *rule,*next_rule;
			struct cls_cursor cursor;
			cls_cursor_init(&cursor,&SGX_oftables[i].cls,NULL);
			CLS_CURSOR_FOR_EACH_SAFE(rule,next_rule,cls_rule,&cursor){
				if(p>elem){
						//overflow: this needs to be handle.
						return;
					}
					//struct sgx_cls_rule * sgx_cls_rule=CONTAINER_OF(rule,struct sgx_cls_rule,cls_rule);
					//buf[p]=sgx_cls_rule->o_cls_rule;
					buf[p]=rule->o_cls_rule;
					p++;
			}
		}
}

//cls_rule_format : We are performing just one part of the entired function.


unsigned int ecall_cls_rule_format(const struct cls_rule *o_cls_rule,struct match *megamatch){
	 struct sgx_cls_rule * sgx_cls_rule;
	 sgx_cls_rule=node_search(o_cls_rule);
	 minimatch_expand(&sgx_cls_rule->cls_rule.match,megamatch);
	 return sgx_cls_rule->cls_rule.priority;
}

uint32_t ecall_rule_calculate_tag(struct cls_rule *o_cls_rule,const struct flow *flow,int table_id)
{

	//Retrieve the cls_rule
	struct sgx_cls_rule *sgx_cls_rule;
	sgx_cls_rule=node_search(o_cls_rule);
	if(minimask_is_catchall(&sgx_cls_rule->cls_rule.match.mask)){
		return 0;
	} else{
		uint32_t secret=SGX_oftables[table_id].eviction_group_id_basis;
		uint32_t hash=flow_hash_in_minimask(flow,&sgx_cls_rule->cls_rule.match.mask,secret);
		return hash;
	}
}




void ecall_miniflow_expand(struct cls_rule *o_cls_rule,struct flow *flow){
	//From untrusted the Pointer the sgx_cls_rule is retrieved.
	struct sgx_cls_rule *sgx_cls_rule=node_search(o_cls_rule);

	//Need to call miniflow_expand to copy the information in the just passed flow struct.
	miniflow_expand(&sgx_cls_rule->cls_rule.match.flow,flow);

}

//These functions are for the ofproto_dpif tables.

//1. Creation and Initialization
void ecall_SGX_table_dpif(int n_tables){
	//I need to create the struct SGX_table_dpif in memory
	int i;
	SGX_table_dpif = xmalloc(n_tables * sizeof(struct SGX_table_dpif));
	for(i=0;i<n_tables;i++){
		SGX_table_dpif[i].catchall_table=NULL;
		SGX_table_dpif[i].other_table=NULL;
	}

}

//2. void ecall_table_update_taggable
int ecall_table_update_taggable(uint8_t table_id){
	//SGX_table_dpif[table_id]
	struct cls_table *catchall, *other;
	struct cls_table *t;
	catchall = other = NULL;
	switch (hmap_count(&SGX_oftables[table_id].cls.tables)) {
	case 0:
		break;
	case 1:
	case 2:
		HMAP_FOR_EACH (t, hmap_node, &SGX_oftables[table_id].cls.tables){
			if(cls_table_is_catchall(t)){
				catchall=t;

			}else if (!other){
				other=t;
			}else{
				other = NULL;
			}
		}
		break;
	default:
		break;
    }
	if (SGX_table_dpif[table_id].catchall_table != catchall || SGX_table_dpif[table_id].other_table != other) {
		SGX_table_dpif[table_id].catchall_table=catchall;
		SGX_table_dpif[table_id].other_table=other;
		return 4;//REV_FLOW_TABLE
	}

	return 0; //No need to do anything to backer.
}

//3. is table_dpif_other_table set?

int ecall_is_sgx_other_table(int id){
	if(SGX_table_dpif[id].other_table){
		return 100;
	}
	return 0;
}

//4. This is a rule_calculate_tag dependencies for tag_the flow.
//using table->other_table.
uint32_t ecall_rule_calculate_tag_s(int id,const struct flow *flow,uint32_t secret)
{
	if(minimask_is_catchall(&SGX_table_dpif[id].other_table->mask)){
		return 0;
	} else{
		uint32_t hash=flow_hash_in_minimask(flow,&SGX_table_dpif[id].other_table->mask,secret);
		return hash;
	}
}


void
ecall_hidden_tables_check(void){
	int i;
	for (i = 0; i + 1 < SGX_n_tables; i++) {
	        enum oftable_flags flags = SGX_oftables[i].flags;
	        enum oftable_flags next_flags = SGX_oftables[i + 1].flags;
	        ovs_assert(!(flags & OFTABLE_HIDDEN) || (next_flags & OFTABLE_HIDDEN));
	    }

}

//DEBUG
void ecall_table_dpif_init(void){
	//Initialization of the table_dpif
	int i;
	for (i = 0; i < N_TABLES; i++) {
		struct SGX_table_dpif *table=&SGX_table_dpif[i];
		table->catchall_table=NULL;
		table->other_table=NULL;

	}
}

//This functions are for ofopgroup_complete()

uint16_t ecall_minimask_get_vid_mask(struct cls_rule *o_cls_rule){
	//Retrieve the cls_rule
	struct sgx_cls_rule *sgx_cls_rule;
	sgx_cls_rule=node_search(o_cls_rule);

	return minimask_get_vid_mask(&sgx_cls_rule->cls_rule.match.mask);

}

uint16_t ecall_miniflow_get_vid(struct cls_rule *o_cls_rule){
	struct sgx_cls_rule *sgx_cls_rule;
	sgx_cls_rule=node_search(o_cls_rule);
	return miniflow_get_vid(&sgx_cls_rule->cls_rule.match.flow);
}

////Dependencies for ofproto_get_vlan
int ecall_ofproto_get_vlan_c(void){
	struct oftable *oftable;
	int i;
	int count=0;
	for(i=0;i<SGX_n_tables;i++) {
		const struct cls_table *table;

		HMAP_FOR_EACH (table, hmap_node, &oftable->cls.tables) {
			if (minimask_get_vid_mask(&table->mask) == VLAN_VID_MASK) {
				const struct cls_rule *rule;

				HMAP_FOR_EACH (rule, hmap_node, &table->rules) {
					//uint16_t vid = miniflow_get_vid(&rule->match.flow);
					count++;
				}
			}
		}
	}
	return count;
}

void ecall_ofproto_get_vlan_r(uint16_t *buf,int elem){
	struct oftable *oftable;
	int i;
	int p=0;
	for(i=0;i<SGX_n_tables;i++) {
		const struct cls_table *table;

		HMAP_FOR_EACH (table, hmap_node, &oftable->cls.tables) {
			if (minimask_get_vid_mask(&table->mask) == VLAN_VID_MASK) {
				const struct cls_rule *rule;

				HMAP_FOR_EACH (rule, hmap_node, &table->rules) {
					uint16_t vid = miniflow_get_vid(&rule->match.flow);
					if(p>elem){
						return;
					}
					buf[p]=vid;
					p++;
				}
			}
		}
	}
}

// Optimized ecalls


void ecall_destroy_rule_if_overlaps(int table_id,struct cls_rule * o_cls_rule) {
	if(ecall_cr_rule_overlaps(table_id, o_cls_rule)) {
		ecall_cls_rule_destroy(o_cls_rule);
	}
}

bool ecall_get_rule_to_evict_if_neccesary(int table_id, struct cls_rule* res) {
	if (ecall_cls_count(table_id)> ecall_table_mflows(table_id)){
		ecall_choose_rule_to_evict_p(table_id, res);
		return true;
	}
	return false;
}

uint32_t ecall_miniflow_expand_and_tag(struct cls_rule *o_cls_rule, struct flow *flow, int table_id) {
	ecall_miniflow_expand(o_cls_rule, flow);
	uint32_t hash;
	hash = ecall_rule_calculate_tag(o_cls_rule, flow, table_id);
	return hash;
}


bool ecall_allocate_cls_rule_if_not_read_only(int table_id, struct cls_rule *o_cls_rule, struct match *match, unsigned int priority) {
	if (ecall_istable_readonly(table_id)){
		return true;
	}
	ecall_cls_rule_init(o_cls_rule, match, priority);
	return false;
}


void ecall_classifer_replace_if_modifiable(int table_id, struct cls_rule* o_cls_rule, struct cls_rule ** cls_rule_rtrn, bool *rule_is_modifiable) {
   ecall_classifier_replace(table_id, o_cls_rule, cls_rule_rtrn);
   *rule_is_modifiable = !(ecall_rule_get_flags(table_id) & OFTABLE_READONLY);
}

// HOT CALLS!
int ecall_start_poller(async_ecall *ctx) {
	//sgx_thread_mutex_init(&ctx->mutex, NULL);
	char buf[128];
  while(1) {
		sgx_spin_lock(&ctx->spinlock);

    if(ctx->run) {
			#ifdef TIMEOUT
			timeout_counter = INIT_TIMER_VALUE;
			#endif
			ENCLAVE_LOG(buf, "Running function %d\n", ctx->function);
      ctx->run = false;
      execute_function(ctx->function, ctx->args, ctx->ret);
      ctx->is_done = true;
			sgx_spin_unlock(&ctx->spinlock);
			ENCLAVE_LOG(buf, "Running function %d done.\n", ctx->function);
      continue;
    }

    sgx_spin_unlock(&ctx->spinlock);

		// Its recommended by intel to add pause actions inside spinlock loops in order to increase performance.
		for(int i = 0; i<3; ++i) {
			__asm __volatile(
					"pause"
			);
		}

		#ifdef TIMEOUT
		timeout_counter--;
		if(timeout_counter <= 0) {
			printf("HOTCALL SERVICE SLEEPING.\n");
			timeout_counter = INIT_TIMER_VALUE;
			ctx->sleeping = true;
			ocall_sleep();
			ctx->sleeping = false;
			//sgx_thread_mutex_lock(&ctx->mutex);
			//sgx_thread_cond_wait(&ctx->cond, &ctx->mutex
			//sgx_thread_mutex_unlock(&ctx->mutex);
		}
		#endif
  }


	sgx_spin_unlock(&ctx->spinlock);

  return 0;
}
