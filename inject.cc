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
    basic_block bb;
    basic_block on_entry, on_exit;
    gimple_stmt_iterator gsi;
    gimple nop;
    int i = 0;
    char *info;
    gasm *asm_or_stmt;
    expanded_location xloc;
    std::string fun_name = current_function_name();
    std::string file_name = DECL_SOURCE_FILE(cfun->decl);
    const tracer_ruleset *rs = tracer_get_ruleset(fun_name);

    vec<tree, va_gc> *inputs = NULL;
    vec<tree, va_gc> *inputs_caller = NULL;
    vec<tree, va_gc> *inputs_callee = NULL;
    vec<tree, va_gc> *outputs = NULL;
    vec<tree, va_gc> *clobbers = NULL;
    tree input, output, clobber, input_caller, input_callee;

    //if (rs == NULL) {
    //    return 0;
    //}
    fprintf(stderr, "LOAD PLUGIN\n");

    const char *array[] = {"__cyg_profile_func_enter",
                           "__cyg_profile_func_exit",
                           "-1"};

    xloc = expand_location(DECL_SOURCE_LOCATION(cfun->decl));
    const char *fname = DECL_SOURCE_FILE(cfun->decl);
    printf("--->> %s\n", fname);

    //
    tree x, x2;
    tree tmp_var, ptr_caller, ptr_callee;
    gcall *call1, *call2;
    gimple_seq seq_tmp = NULL;
    x = builtin_decl_implicit (BUILT_IN_RETURN_ADDRESS);
    call1 = gimple_build_call (x, 1, integer_zero_node);
    ptr_callee = create_tmp_var (ptr_type_node, "return_addr");
    gimple_call_set_lhs (call1, ptr_callee);
    
    x2 = builtin_decl_implicit (BUILT_IN_RETURN_ADDRESS);
    call2 = gimple_build_call (x2, 1, integer_one_node);
    ptr_caller = create_tmp_var (ptr_type_node, "return_addr");
    gimple_call_set_lhs (call2, ptr_caller);


    printf("Process function: %s\n", current_function_name());

    // Build char array type with function name
    tree str, hex_xlat;
    asprintf(&info, "## %s   ", current_function_name());
    size_t len = strlen (info) + 1;
    info[len-1] = 10;
    str = build_string (len, info);
    TREE_TYPE (str) = build_array_type_nelts (char_type_node, len);
    TREE_READONLY (str) = 1;
    TREE_STATIC (str) = 1;
    str = build_fold_addr_expr (str);
    free(info);

    // Build char array type with function name
    /*
    asprintf(&info, "0123456789abcdef");
    len = strlen (info) + 1;
    hex_xlat = build_string (len, info);
    TREE_TYPE (hex_xlat) = build_array_type_nelts (char_type_node, len);
    TREE_READONLY (hex_xlat) = 1;
    TREE_STATIC (hex_xlat) = 1;
    hex_xlat = build_fold_addr_expr (hex_xlat);
    free(info);   
    */
    // input current function name
    input = build_tree_list(NULL_TREE, build_const_char_string(3, "rm"));
    input = chainon(NULL_TREE, build_tree_list(input, str));

    // 
    input_caller = build_tree_list(NULL_TREE, build_const_char_string(3, "rm"));
    input_caller = chainon(NULL_TREE, build_tree_list(input_caller, ptr_caller));

    input_callee = build_tree_list(NULL_TREE, build_const_char_string(3, "rm"));
    input_callee = chainon(NULL_TREE, build_tree_list(input_callee, ptr_callee));




//    debug_tree(input);
//    debug_tree(tmp_var);


//    output = build_tree_list(NULL_TREE, build_const_char_string(3, "=r"));
//    output = chainon(NULL_TREE, build_tree_list(output, msg_str));

//    clobber = build_tree_list(NULL_TREE, build_const_char_string(6, "%%rsi"));
//    clobber = chainon(NULL_TREE, build_tree_list(output, msg_str));

    vec_safe_push(inputs, input);
    vec_safe_push(inputs_caller, input_caller);
//    vec_safe_push(outputs, output);
//    vec_safe_push(clobbers, clobber);

//    gsi = gsi_last_bb(on_entry);


    if (!(DECL_DECLARED_INLINE_P (cfun->decl))
            && !flag_instrument_functions_exclude_p (cfun->decl)
            && !(DECL_EXTERNAL (cfun->decl)) ) {

        on_entry = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
        gsi = gsi_start_bb(on_entry);
        
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
         gsi_insert_before(&gsi, call1, GSI_NEW_STMT);

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

         nop = gimple_build_asm_vec("mov $13, %%rdx", NULL, NULL, NULL, NULL);
         asm_or_stmt = as_a_gasm(nop);
         gimple_asm_set_volatile(asm_or_stmt, true);
         gsi_insert_before(&gsi, nop, GSI_NEW_STMT);

         nop = gimple_build_asm_vec("mov %0, %%rsi", inputs, NULL, NULL, NULL);
         asm_or_stmt = as_a_gasm(nop);
         gimple_asm_set_volatile(asm_or_stmt, true);
         gsi_insert_before(&gsi, nop, GSI_NEW_STMT);




tree lab = build_decl (gimple_location (gsi_stmt (gsi)), LABEL_DECL, NULL_TREE, void_type_node);
DECL_ARTIFICIAL(lab) = 0;
DECL_IGNORED_P(lab) = 1;
DECL_CONTEXT(lab) = current_function_decl;
DECL_NAME(lab) = get_identifier("1:");

location_t loc = gimple_location (gsi_stmt (gsi));
tree label = create_artificial_label (loc);
gsi_insert_before (&gsi, gimple_build_label (lab), GSI_SAME_STMT);


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



//        }
    }
    
    return 0;
}


#define PREF_SYM        "__ksymtab_"




static void test(void *event_data, void *user_data){
    tree node;
    node = (tree)event_data;
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

    PASS_INFO(callgraph, "tsan0", 1, PASS_POS_INSERT_AFTER);
    //PASS_INFO(callgraph, "ssa", 1, PASS_POS_INSERT_BEFORE);
    // Register the phase right after omplower
    struct register_pass_info pass_info;

    register_callback(plugin_name, PLUGIN_INFO, NULL, &callgraph_plugin_info);
    register_callback (plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &callgraph_pass_info);
    register_callback(plugin_name, PLUGIN_FINISH_DECL, test, NULL);
    return 0;
}



