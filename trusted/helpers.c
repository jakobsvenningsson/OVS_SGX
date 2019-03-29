#include "helpers.h"

//1. Initialization of hmap table
void sgx_table_cls_init(){
	SGX_hmap_table = xmalloc(sizeof(struct sgx_cls_table));
	hmap_init(&SGX_hmap_table->cls_rules);
}

/*2. Node_search: This method is in charge of the searching of a cls_rule based on
 hash computed from the pointer holding the cls_rule in untrusted memory
*/
struct sgx_cls_rule* node_search(const struct cls_rule *out){
	struct sgx_cls_rule *rule;
	HMAP_FOR_EACH_WITH_HASH(rule,hmap_node,hash_pointer(out,0),&SGX_hmap_table->cls_rules){
		return rule;
	}
	return NULL;
}

//3. Node_search_evict: Searches for a rule that match the struct eviction_group pointer
struct sgx_cls_rule* node_search_evict(struct eviction_group *out){
	struct sgx_cls_rule *rule;
	HMAP_FOR_EACH(rule,hmap_node,&SGX_hmap_table->cls_rules){
		if(rule->evict_group==out){
			return rule;
		}
	}
	return NULL;
}

//4. Node_insert: This function insert a new sgx_cls_rule to the hmap table.
struct sgx_cls_rule* node_insert(uint32_t hash){
	struct sgx_cls_rule * new=xmalloc(sizeof(struct sgx_cls_rule));
	memset(new,0,sizeof(struct sgx_cls_rule));
	new->hmap_node.hash=hash;
	//We can find if the rule is already installed.

	hmap_insert(&SGX_hmap_table->cls_rules,&new->hmap_node,new->hmap_node.hash);

	struct sgx_cls_rule *rule;
	HMAP_FOR_EACH_WITH_HASH(rule,hmap_node,hash,&SGX_hmap_table->cls_rules){

	}
	return new;
}

//5. node_delete: deletes sgx_rule from the hmap table and free the sgx_cls_rule
void node_delete(struct cls_rule *out){
	struct sgx_cls_rule *rule;
	rule=node_search(out);
	hmap_remove(&SGX_hmap_table->cls_rules,&rule->hmap_node);
	free(rule);
}
