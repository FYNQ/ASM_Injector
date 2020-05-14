#ifndef _GNU_SOURCE
#define _GNU_SOURCE // Required to use asprintf()
#endif


#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <sstream>
#include <sys/stat.h>
#include <json-c/json.h>

#define HAVE_DECL_BASENAME 1
#include <libgen.h>
#include <libiberty.h>
#include "gcc-common.h"
#include "tree-iterator.h"
#include "pretty-print.h"
#include "gomp-constants.h"

  #include "tree-pass.h"
  #include "context.h"
  #include "function.h"
  #include "tree.h"
  #include "tree-ssa-alias.h"
  #include "internal-fn.h"
  #include "is-a.h"
  #include "predict.h"
  #include "basic-block.h"
  #include "gimple-expr.h"
  #include "gimple.h"
  #include "gimple-pretty-print.h"
  #include "gimple-iterator.h"
  #include "gimple-walk.h"
  #include "cgraph.h"
  #include "tree-iterator.h"
  #include "langhooks.h"
  #include <print-tree.h>
  #include "line-map.h"
  #include "c-tree.h"


#include "rules.h"
#define INDENT(SPACE) do { \
  int i; for (i = 0; i<SPACE; i++) pp_space (pp); } while (0)




#define TDF_VOPS    (1 << 6)    /* display virtual operands */



using namespace std;


static char *rfile = NULL;

typedef map<string, tracer_ruleset> tracer_rule_map;
static tracer_rule_map rules;




#define PREF_SYM        "__ksymtab_"

#define VAR_FUNCTION_OR_PARM_DECL_CHECK(NODE) \
      TREE_CHECK3(NODE,VAR_DECL,FUNCTION_DECL,PARM_DECL)

#define DECL_THIS_EXTERN(NODE) \
  DECL_LANG_FLAG_2 (VAR_FUNCTION_OR_PARM_DECL_CHECK (NODE)) 


#define DECL_THIS_STATIC(NODE) \
  DECL_LANG_FLAG_6 (VAR_FUNCTION_OR_PARM_DECL_CHECK (NODE)) 

#define NODE_DECL(node) (node)->decl
#define NODE_SYMBOL(node) (node)

char *g_prefix = NULL;



 

// We must assert that this plugin is GPL compatible
int plugin_is_GPL_compatible;

static struct plugin_info pic_gcc_plugin_info = { "1.0", "PIC plugin" };

struct gcc_variable {
          struct varpool_node * inner;
};
typedef struct gcc_variable gcc_variable;




#define NO_FILE  "no_file"


static struct plugin_info callgraph_plugin_info = {
    .version    = "2020121",
    .help       = "callgraph plugin\n",
};

static tree callback_op(tree *t, int *, void *data) {
    return NULL;
}


static tree callback_stmt(gimple_stmt_iterator *gsi,
                    bool *handled_all_ops,  struct walk_stmt_info *wi) {

}


static unsigned int check() {

}

typedef char *char_p;

static bool
flag_instrument_functions_exclude_p (tree fndecl)
{
  vec<char_p> *v;

  v = (vec<char_p> *) flag_instrument_functions_exclude_functions;
  if (v && v->length () > 0)
    {
      const char *name;
      int i;
      char *s;

      name = lang_hooks.decl_printable_name (fndecl, 0);
      FOR_EACH_VEC_ELT (*v, i, s)
    if (strstr (name, s) != NULL)
      return true;
    }

  v = (vec<char_p> *) flag_instrument_functions_exclude_files;
  if (v && v->length () > 0)
    {
      const char *name;
      int i;
      char *s;

      name = DECL_SOURCE_FILE (fndecl);
      FOR_EACH_VEC_ELT (*v, i, s)
    if (strstr (name, s) != NULL)
      return true;
    }

  return false;
}




static unsigned int callgraph_execute(){
    basic_block on_entry, on_exit;
    gimple_stmt_iterator gsi;
    gimple nop;
    char *info;
    gasm *asm_or_stmt;
    gimple_seq seq = NULL;
    expanded_location xloc;
    std::string fun_name = current_function_name();
    std::string file_name = DECL_SOURCE_FILE(cfun->decl);
    const tracer_ruleset *rs = tracer_get_ruleset(fun_name);

    vec<tree, va_gc> *ins_fun_name = NULL;
    vec<tree, va_gc> *ins_caller = NULL;
    vec<tree, va_gc> *labels = NULL;
    vec<tree, va_gc> *ins_callee = NULL;
    vec<tree, va_gc> *ins_hex_xlat = NULL;
    vec<tree, va_gc> *ins_buf = NULL;
    vec<tree, va_gc> *outs_buf = NULL;
    tree in_fun_name, in_caller, in_callee, in_hex_xlat, in_buf, out_buf;

    //if (rs == NULL) {
    //    return 0;
    //}
    fprintf(stderr, "LOAD PLUGIN\n");

    xloc = expand_location(DECL_SOURCE_LOCATION(cfun->decl));
    const char *fname = DECL_SOURCE_FILE(cfun->decl);
    printf("--->> %s\n", fname);

    //
    tree x, x2;
    tree ptr_caller, ptr_callee;
    gcall *call1, *call2;
    gimple_seq seq_tmp = NULL;
    x = builtin_decl_implicit (BUILT_IN_RETURN_ADDRESS);
    call1 = gimple_build_call (x, 1, integer_one_node);
    ptr_callee = create_tmp_var (ptr_type_node, "return_addr");
    gimple_call_set_lhs (call1, ptr_callee);
    gimple_set_location(call1, cfun->function_start_locus);
//    gimple_seq_add_stmt(&seq, call1);


    x2 = builtin_decl_implicit (BUILT_IN_RETURN_ADDRESS);
    call2 = gimple_build_call (x2, 1, integer_one_node);
    ptr_caller = create_tmp_var (ptr_type_node, "return_addr");
    gimple_call_set_lhs (call2, ptr_caller);


    printf("Process function: %s\n", current_function_name());

    // Build char array type with function name
    tree fun_str, hex_xlat, obuf;
    asprintf(&info, "## %s   ", current_function_name());
    size_t len = strlen (info) + 1;
    info[len-1] = 0x0a;
    fun_str = build_string (len, info);
    TREE_TYPE (fun_str) = build_array_type_nelts (char_type_node, len);
    TREE_READONLY (fun_str) = 1;
    TREE_STATIC (fun_str) = 1;
    fun_str = build_fold_addr_expr (fun_str);
    free(info);

    // Build char array type with translation name
    asprintf(&info, "0123456789abcdef");
    //asprintf(&info, "%x");
    len = strlen (info) + 1;
    hex_xlat = build_string (len, info);
    TREE_TYPE (hex_xlat) = build_array_type_nelts (char_type_node, len);
    TREE_READONLY (hex_xlat) = 1;
    TREE_STATIC (hex_xlat) = 1;
    hex_xlat = build_fold_addr_expr (hex_xlat);
    free(info);   
    fprintf(stderr, "---------------------------------------------------\n");
    
    
    // Build char array for addr output buffer
    
    asprintf(&info, "buf_%s", current_function_name());
	tree __str_id = get_identifier(info);

	/* create a new type for const char */
	tree __str_array_type = build_array_type(char_type_node, build_index_type(build_int_cst(NULL_TREE, 18)));
	tree __str_type = build_pointer_type(char_type_node);
	tree __str_array_ptr_type = build_pointer_type(__str_array_type);

	tree __str_decl = build_decl(UNKNOWN_LOCATION, VAR_DECL, __str_id, __str_type);

	TREE_STATIC(__str_decl) = true;

	/* external linkage */
	TREE_PUBLIC(__str_decl) = false;

	DECL_CONTEXT(__str_decl) = NULL_TREE;
	TREE_USED(__str_decl) = true;

	/* initialization to constant/read-only string */
	tree __str_init_val = build_string(18, "Global Value: %u\n");
	TREE_TYPE(__str_init_val) = __str_array_type;
	TREE_CONSTANT(__str_init_val) = false;
	TREE_STATIC(__str_init_val) = true;
	TREE_READONLY(__str_init_val) = true;

	tree adr_expr = build1(ADDR_EXPR, __str_array_ptr_type, __str_init_val);
	tree nop_expr = build1(NOP_EXPR, __str_type, adr_expr);

	DECL_INITIAL(__str_decl) = nop_expr;

	layout_decl(__str_decl, 16);
	rest_of_decl_compilation(__str_decl, 1, 0); 
    free(info);
	//return __str_decl;
    debug_tree(__str_decl);





    // input current function name
    in_fun_name = build_tree_list(NULL_TREE, build_const_char_string(3, "rm"));
    in_fun_name = chainon(NULL_TREE, build_tree_list(in_fun_name, fun_str));

    in_hex_xlat = build_tree_list(NULL_TREE, build_const_char_string(3, "rm"));
    in_hex_xlat = chainon(NULL_TREE, build_tree_list(in_hex_xlat, hex_xlat));
 
    out_buf = build_tree_list(NULL_TREE, build_const_char_string(3, "=m"));
    out_buf = chainon(NULL_TREE, build_tree_list(out_buf, __str_decl));

    in_buf = build_tree_list(NULL_TREE, build_const_char_string(3, "rm"));
    in_buf = chainon(NULL_TREE, build_tree_list(in_buf, __str_decl));





 //   in_caller = build_tree_list(NULL_TREE, build_const_char_string(3, "rm"));
 //   in_caller = chainon(NULL_TREE, build_tree_list(in_caller, ptr_caller));

//    in_callee = build_tree_list(NULL_TREE, build_const_char_string(3, "rm"));
//    in_callee = chainon(NULL_TREE, build_tree_list(in_callee, ptr_callee));

        // Assemble built-in calls to get caller/callee address
        tree ret_addr, ret_addr2, builtin_decl;
        gimple g1, g2;
        builtin_decl = builtin_decl_implicit (BUILT_IN_RETURN_ADDRESS);
        g1 = gimple_build_call (builtin_decl, 1, integer_zero_node);
        ret_addr = make_ssa_name (ptr_type_node);
        gimple_call_set_lhs (g1, ret_addr);
        gimple_set_location (g1, cfun->function_start_locus);

        in_caller = build_tree_list(NULL_TREE, build_const_char_string(3, "rm"));
        in_caller = chainon(NULL_TREE, build_tree_list(in_caller, ret_addr));
        vec_safe_push(ins_caller, in_caller);

      builtin_decl = builtin_decl_implicit (BUILT_IN_RETURN_ADDRESS);
      g2 = gimple_build_call (builtin_decl, 1, integer_one_node);
      ret_addr2 = make_ssa_name (ptr_type_node);
      gimple_call_set_lhs (g2, ret_addr2);
      gimple_set_location (g2, cfun->function_start_locus);

      //gimple_seq_add_stmt_without_update (&seq, g);
      //gsi_insert_seq_on_edge_immediate (e, seq);
      in_callee = build_tree_list(NULL_TREE, build_const_char_string(3, "rm"));
      in_callee = chainon(NULL_TREE, build_tree_list(in_callee, ret_addr2));
      vec_safe_push(ins_callee, in_callee);



    vec_safe_push(ins_fun_name, in_fun_name);
    vec_safe_push(ins_hex_xlat, in_hex_xlat);
    vec_safe_push(outs_buf, out_buf);
    vec_safe_push(ins_buf, in_buf);

    /*
    used for exit instrumentation
    gsi = gsi_last_bb(on_entry);
    */

    if (!(DECL_DECLARED_INLINE_P (cfun->decl))
            && !flag_instrument_functions_exclude_p (cfun->decl)
            && !(DECL_EXTERNAL (cfun->decl)) ) {
        
        on_entry = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
        gsi = gsi_start_bb(on_entry);
        nop = gimple_build_asm_vec("sub $-128,%%rsp", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);


       // ---------------------------------------------------------------
       // Restore all register on stack
        nop = gimple_build_asm_vec("pop %%r11", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);

        nop = gimple_build_asm_vec("pop %%rcx", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);

        nop = gimple_build_asm_vec("pop %%rax", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);
        
        nop = gimple_build_asm_vec("pop %%rdi", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);

        nop = gimple_build_asm_vec("pop %%rdx", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT); 

        nop = gimple_build_asm_vec("pop %%rsi", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT); 

        nop = gimple_build_asm_vec("pop %%rbp", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);
        
        // ---------------------------------------------------------------
        // Write function name to stdout

        nop = gimple_build_asm_vec("syscall", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true); 
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);
        
        nop = gimple_build_asm_vec("movq $1, %%rax", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);

        nop = gimple_build_asm_vec("movq $1, %%rdi", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);

        nop = gimple_build_asm_vec("mov $16, %%rdx", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);

        // Write function name
        /*
        nop = gimple_build_asm_vec("mov %0, %%rsi", ins_fun_name, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);
        */

        nop = gimple_build_asm_vec("lea %0, %%rsi", ins_buf, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);




      //nop = gimple_build_asm_vec("movdqu %%xmm5, %0", NULL, outs_buf, NULL,  NULL);
      nop = gimple_build_asm_vec("movups %%xmm5, %0", NULL, outs_buf, NULL,  NULL);
      asm_or_stmt = as_a_gasm(nop);
      gimple_asm_set_volatile(asm_or_stmt, true);
      gsi_insert_before(&gsi, nop, GSI_NEW_STMT);


      nop = gimple_build_asm_vec("bswap %%rdi\n\t               \
                                  movq %%rdi, %%xmm1\n\t        \
                                  pcmpeqw %%xmm4, %%xmm4\n\t    \
                                  psrlw   $12, %%xmm4\n\t      \
                                  packuswb %%xmm4, %%xmm4\n\t   \
                                  movdqa  %%xmm1, %%xmm0\n\t    \
                                  psrlw   $4, %%xmm1\n\t        \
                                  punpcklbw %%xmm0, %%xmm1\n\t  \
                                  pand    %%xmm4, %%xmm1\n\t    \
                                  pshufb  %%xmm1, %%xmm5\n\t", NULL, NULL, NULL, NULL);
      
      asm_or_stmt = as_a_gasm(nop);

      gimple_asm_set_volatile(asm_or_stmt, true);
      gsi_insert_before(&gsi, nop, GSI_NEW_STMT);
        

      nop = gimple_build_asm_vec("movq %0, %%rdi", ins_caller, NULL, NULL,  NULL);
      asm_or_stmt = as_a_gasm(nop);
      gimple_asm_set_volatile(asm_or_stmt, true);
      gsi_insert_before(&gsi, nop, GSI_NEW_STMT);

      nop = gimple_build_asm_vec("movdqu (%0), %%xmm5", ins_hex_xlat, NULL, NULL,  NULL);
      asm_or_stmt = as_a_gasm(nop);
      gimple_asm_set_volatile(asm_or_stmt, true);
      gsi_insert_before(&gsi, nop, GSI_NEW_STMT);


/*
      nop = gimple_build_asm_vec("movq %0, %%rax", ins_hex_xlat, NULL, NULL,  NULL);
      asm_or_stmt = as_a_gasm(nop);
      gimple_asm_set_volatile(asm_or_stmt, true);
      gsi_insert_before(&gsi, nop, GSI_NEW_STMT);

*/
        // ---------------------------------------------------------------
        // Push all register on stack
        nop = gimple_build_asm_vec("push %%rbp", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);

        nop = gimple_build_asm_vec("push %%rsi", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);


        nop = gimple_build_asm_vec("push %%rdx", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);

        nop = gimple_build_asm_vec("push %%rdi", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);

        nop = gimple_build_asm_vec("push %%rax", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);

        nop = gimple_build_asm_vec("push %%rcx", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);

        nop = gimple_build_asm_vec("push %%r11", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);

        nop = gimple_build_asm_vec("add $-128,%%rsp", NULL, NULL, NULL, NULL);
        asm_or_stmt = as_a_gasm(nop);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gsi_insert_before(&gsi, nop, GSI_NEW_STMT);




      gsi_insert_before(&gsi, g1, GSI_NEW_STMT);
      gsi_insert_before(&gsi, g2, GSI_NEW_STMT);



//        }
    }
    
    return 0;
}


#define PREF_SYM        "__ksymtab_"




static void test(void *event_data, void *user_data){
    tree node;
    node = (tree)event_data;
//    debug_tree(node);
    const char *name;
    if (TREE_CODE(node) != PARM_DECL && !DECL_EXTERNAL(node)) {
        if (DECL_NAME (node)) {

            /* consider only project files no compiler includes
             * -> It is just a fix, I do not know the proper way atm */
            int ret = strncmp("/usr", DECL_SOURCE_FILE(node), strlen("/usr"));
            if (ret == 0)
                return;
            name = IDENTIFIER_POINTER(DECL_NAME(node));
        }
    }
}




#define PASS_NAME callgraph

#define NO_GATE
#define TODO_FLAGS_FINISH TODO_dump_func | TODO_verify_stmts | TODO_update_ssa_no_phi |     TODO_verify_flow


#include "gcc-generate-gimple-pass.h"



int plugin_init (struct plugin_name_args *plugin_info,
             	 struct plugin_gcc_version *version){
    int i;
    const char * const plugin_name = plugin_info->base_name;
	// We check the current gcc loading this plugin against the gcc we used to
	// created this plugin
	if (!plugin_default_version_check (version, &gcc_version)) {
        fprintf(stderr, "This GCC plugin is for version %d. %d", \
                GCCPLUGIN_VERSION_MAJOR, GCCPLUGIN_VERSION_MINOR);
		return 1;
    }
    for (i = 0; i < plugin_info->argc; ++i) {
        if (strcmp (plugin_info->argv[i].key, "rules") == 0) {
            asprintf(&rfile, "%s", plugin_info->argv[i].value);
        }
    }
    if (rfile == NULL) {
        fprintf(stderr, "Error: No rule file found\n"); 
        return 0;
    }
    string rules_file(rfile);
    FILE *rfl = fopen(rules_file.c_str(), "rb");
    if (!rfl) {
        perror("Error");
        fprintf(stderr, "Error: unable to open %s.\n",
            rules_file.c_str());
        return 1;
    }

    tracer_parse_rules(rfl, rules_file.c_str());
    fclose(rfl);

//    PASS_INFO(callgraph, "ssa", 1, PASS_POS_INSERT_AFTER);
    PASS_INFO(callgraph, "ssa", 1, PASS_POS_INSERT_BEFORE);
    // Register the phase right after omplower
    struct register_pass_info pass_info;

    register_callback(plugin_name, PLUGIN_INFO, NULL, &callgraph_plugin_info);
    register_callback (plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &callgraph_pass_info);
    register_callback(plugin_name, PLUGIN_FINISH_DECL, test, NULL);
    return 0;
}



