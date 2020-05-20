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


gimple_seq pop_stack() {
    gasm *asm_or_stmt;
    gimple_seq seq = NULL;
    gimple g;


    g = gimple_build_asm_vec("pop %%rsp", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("pop %%rbx", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("pop %%rbp", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("pop %%rsi", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("pop %%rdx", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("pop %%rdi", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("pop %%rax", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("pop %%rcx", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("pop %%r11", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("sub $-128,%%rsp", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
//    gimple_seq_add_stmt(&seq, g);
    return seq;
}



gimple_seq push_stack() {
    gasm *asm_or_stmt;
    gimple_seq seq = NULL;
    gimple g;

    g = gimple_build_asm_vec("add $-128,%%rsp", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
//    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("push %%r11", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("push %%rcx", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("push %%rax", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("push %%rdi", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("push %%rdx", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("push %%rsi", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("push %%rbp", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    // ----- 
    g = gimple_build_asm_vec("push %%rbx", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("push %%rsp", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);




    return seq;
}

gimple_seq write_cstring(const char *msg){
//    char *msg;
    size_t len;
//    asprintf(&msg, "%s%u\n", _msg);
    gasm *asm_or_stmt;
    gimple_seq seq = NULL;
    gimple g;
    tree tmsg, tlen, out_buf, buf_len;

    vec<tree, va_gc> *vec_msg = NULL;
    vec<tree, va_gc> *vec_msg_len = NULL;

    len = strlen(msg);
    tlen = build_int_cst(integer_type_node, len);

    buf_len = build_tree_list(NULL_TREE, build_const_char_string(2, "r"));
    buf_len = chainon(NULL_TREE, build_tree_list(buf_len, tlen));
    vec_safe_push(vec_msg_len, buf_len);

    len = strlen(msg) + 1;
    tmsg = build_string (len, msg);
    TREE_TYPE (tmsg) = build_array_type_nelts (char_type_node, len);
    TREE_READONLY (tmsg) = 1;
    TREE_STATIC (tmsg) = 1;
    tmsg = build_fold_addr_expr (tmsg);

    out_buf = build_tree_list(NULL_TREE, build_const_char_string(3, "rm"));
    out_buf = chainon(NULL_TREE, build_tree_list(out_buf, tmsg));
    vec_safe_push(vec_msg, out_buf);

    g = gimple_build_asm_vec("mov %0, %%rsi", vec_msg, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("movq $1, %%rdi", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    /* clear register  */
    g = gimple_build_asm_vec("xor %%rdx, %%rdx", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);
    
    /* Set len*/
    g = gimple_build_asm_vec("movl %0, %%edx", vec_msg_len, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("movq $1, %%rax", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("syscall", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true); 
    gimple_seq_add_stmt(&seq, g);
    //free(msg);
 
    return seq;
}


void create_buf(){

}

gimple_seq wr_addr_tree(tree addr) {
    char *buf;
    size_t len;
    gasm *asm_or_stmt;
    gimple_seq seq = NULL;
    tree in_addr;
    gimple g;

    vec<tree, va_gc> *vec_msg = NULL;
    vec<tree, va_gc> *vec_xlat = NULL;
    vec<tree, va_gc> *vec_msg_len = NULL;
    vec<tree, va_gc> *vec_out_buf = NULL;
    vec<tree, va_gc> *vec_test = NULL;
    vec<tree, va_gc> *vec_bout = NULL;
    vec<tree, va_gc> *vec_addr = NULL;

    // create vector variable for addr
    tree addr_in = build_tree_list(NULL_TREE, build_const_char_string(3, "rm"));
    addr_in = chainon(NULL_TREE, build_tree_list(addr_in, addr));
    vec_safe_push(vec_addr, addr_in);


    char *info;
    asprintf(&info, "0123456789abcdef"); 
    len = strlen (info) + 1; 
    tree hex_xlat = build_string (len, info); 
    TREE_TYPE (hex_xlat) = build_array_type_nelts (char_type_node, len); 
    TREE_READONLY (hex_xlat) = 0; 
    TREE_STATIC (hex_xlat) = 1; 
    hex_xlat = build_fold_addr_expr (hex_xlat); 
    free(info); 

    // translation table
    tree in_hex_xlat = build_tree_list(NULL_TREE, build_const_char_string(2, "r"));
    in_hex_xlat = chainon(NULL_TREE, build_tree_list(in_hex_xlat, hex_xlat));
    vec_safe_push(vec_xlat, in_hex_xlat);

    // load xlat tabel to rdx    
    //g = gimple_build_asm_vec("mov %0, %%rdx", vec_xlat, NULL, NULL,  NULL);
    g = gimple_build_asm_vec("lea -16(%%rsp), %%rsi", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);


    // load addr to reg

    g = gimple_build_asm_vec("mov %%rbp, %%rcx\n\t", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);



    g = gimple_build_asm_vec("add $8, %%rcx\n\t", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);


    g = gimple_build_asm_vec("movq (%%rcx), %%rdi", NULL, NULL, NULL,  NULL);
    //g = gimple_build_asm_vec("mov %0, %%rdi", vec_addr, NULL, NULL,  NULL);
    //g = gimple_build_asm_vec("mov $0xdeadbeef, %%rdi", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);




  
    // create array type
    tree __str_array_type = build_array_type(char_type_node,\
                               build_index_type(build_int_cst(NULL_TREE, 50)));
    tree __str_type = build_pointer_type(char_type_node);

    // create buffer variable for output
    tree dec_node = build_decl(UNKNOWN_LOCATION, VAR_DECL, NULL_TREE, __str_type);
    DECL_NAME(dec_node) = create_tmp_var_name("buf");
    DECL_ARTIFICIAL(dec_node) = 1;
    TREE_STATIC(dec_node) = 1;
    //varpool_finalize_decl(dec_node);
    tree out_buf = build_tree_list(NULL_TREE, build_const_char_string(3, "=m"));
    out_buf = chainon(NULL_TREE, build_tree_list(out_buf, dec_node));
    vec_safe_push(vec_bout, out_buf);


    //g = gimple_build_asm_vec("lea %0, %%rsi", NULL, vec_bout, NULL,  NULL);
    /*
    g = gimple_build_asm_vec("lea -16(%%rsp), %%rsi", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);
    */
  g = gimple_build_asm_vec("mov %%rsp, %%rcx", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);


    g = gimple_build_asm_vec("movq $0x6665646362613938, %%rdx", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("push %%rdx", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("movq $0x3736353433323130, %%rdx", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("push %%rdx", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("mov %%rsp, %%rdx", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);



    g = gimple_build_asm_vec("xor %%eax, %%eax", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("mov $4, %%ecx", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);
 

    int i;
    for (i=0; i<16; i++) {
    g = gimple_build_asm_vec("rol $4,%%rdi\n\t", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);


    g = gimple_build_asm_vec("mov %%dil,%%al\n\t", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("and $0xf,%%eax\n\t", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);


    g = gimple_build_asm_vec("mov (%%rdx,%%rax, 1), %%al\n\t", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("mov %%al,(%%rsi)\n\t", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("inc %%rsi\n\t", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);
 

    g = gimple_build_asm_vec("dec %%ecx\n\t", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);


    }
    // print to stdout
    g = gimple_build_asm_vec("movq $1, %%rax", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("movq %%rax, %%rdi", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    /* Set len */
    g = gimple_build_asm_vec("mov $16, %%rdx", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    //g = gimple_build_asm_vec("lea %0, %%rsi", NULL, vec_bout, NULL,  NULL);
    g = gimple_build_asm_vec("sub %%rdx, %%rsi", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("syscall", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("pop %%rdx", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("pop %%rdx", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    return seq;
}

void instrument_calls() {
    basic_block bb;
    gimple_stmt_iterator gsi;
    gimple_seq seq_pre = NULL;
    gimple_seq seq_post = NULL;
    gimple_seq seq = NULL;
    gimple stmt;

    FOR_EACH_BB_FN (bb, cfun) {
        for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
            stmt = gsi_stmt(gsi);
            if (is_gimple_call(stmt)) {

                tree fndecl = gimple_call_fn(as_a <gcall *>(stmt));
                seq = wr_addr_tree(fndecl);
                gsi_insert_seq_after(&gsi, seq, GSI_NEW_STMT);

                debug_tree(SSA_NAME_VAR (fndecl));
                print_node_brief (stderr, "", fndecl, 0);

                if (!fndecl) {
                    /* indirect call */
                    print_gimple_stmt (stderr, stmt, 0, 0);
//                    debug_tree(fndecl);
                }
            }
        }
    }
}

void instrument_entry(){
    basic_block on_entry, on_exit;
    gimple_stmt_iterator gsi;
    gimple_seq seq = NULL;
    expanded_location xloc;
    //const tracer_ruleset *rs = tracer_get_ruleset(fun_name);
    char *sep;
    char *arrow;
    asprintf(&arrow, "---->");
    asprintf(&sep, ":");

    //if (rs == NULL) {
    //    return 0;
    //}
    fprintf(stderr, "LOAD PLUGIN\n");

    xloc = expand_location(DECL_SOURCE_LOCATION(cfun->decl));
    const char *fname = DECL_SOURCE_FILE(cfun->decl);
    printf("--->> %s\n", fname);
    char *fun_name;
    asprintf(&fun_name, "::%s::\n", current_function_name());
    
    // Assemble built-in calls to get caller/callee address
    tree addr0, addr1, builtin_decl;
    gimple g0, g1;
    builtin_decl = builtin_decl_implicit (BUILT_IN_FRAME_ADDRESS);
    g0 = gimple_build_call (builtin_decl, 1, integer_zero_node);
    addr0 = make_ssa_name (ptr_type_node);
    gimple_call_set_lhs (g0, addr0);
    gimple_set_location (g0, cfun->function_start_locus);


    builtin_decl = builtin_decl_implicit (BUILT_IN_FRAME_ADDRESS);
    g1 = gimple_build_call (builtin_decl, 1, integer_one_node);
    addr1 = make_ssa_name (ptr_type_node);
    gimple_call_set_lhs (g1, addr1);
    gimple_set_location (g1, cfun->function_start_locus);


    /*
    used for exit instrumentation
    gsi = gsi_last_bb(on_entry);
    */

    if (!(DECL_DECLARED_INLINE_P (cfun->decl))
            && !flag_instrument_functions_exclude_p (cfun->decl)
            && !(DECL_EXTERNAL (cfun->decl)) ) {

        //debug_tree(DECL_ARGUMENTS(current_function_decl));
        on_entry = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
        //on_entry = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
        //on_entry = ENTRY_BLOCK_PTR_FOR_FN(cfun);
      gsi = gsi_start_bb(on_entry);
//        gsi = gsi_last_bb(on_entry);
        create_buf();    
        /* Pop stack*/
        seq = pop_stack();
        gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);

//        seq = write_cstring(sep);//XX
//        gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);

        
//        seq = wr_addr_tree(addr0);
//        gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);
//        gsi_insert_after(&gsi, seq, GSI_NEW_STMT);
        /* call __builtin_return_address(1) 
         * and print to stderr */
//        seq = write_cstring(fname);//XXX
//        gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);
//        seq = write_cstring(fname);//XXX
//        gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);


        seq = write_cstring(fun_name);//XXX
        gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);


//        seq = wr_addr_tree(addr0);
//        gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);
//        gsi_insert_before(&gsi, g0, GSI_NEW_STMT);

       
//        seq = write_cstring("::");//XXX
//        gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);


        seq = wr_addr_tree(addr0);
        gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);
//        gsi_insert_before(&gsi, g0, GSI_NEW_STMT);

        /* Push stack*/
        seq = push_stack();
        gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);
        //gsi_insert_seq_after(&gsi, seq, GSI_NEW_STMT);
    }
    
    free(sep);
    free(arrow);
    free(fun_name);
}

static unsigned int callgraph_execute(){
    instrument_calls();
    instrument_entry();
//    instrument_exit();
}


#define PREF_SYM        "__ksymtab_"


static void start_unit(void *event_data, void *user_data){
    char *buf;
    size_t len;


    printf("## --------------- start ----------------");
    /*
    asprintf(&buf, "buf");
    tree __str_id = get_identifier(buf);
    len = 16;//strlen (info) + 1;
    // create a new type for const char
    
    tree __str_array_type = build_array_type(char_type_node,\
            build_index_type(build_int_cst(NULL_TREE, len)));
    tree __str_type = build_pointer_type(char_type_node);
    tree __str_array_ptr_type = build_pointer_type(__str_array_type);

    tree __str_decl = build_decl(UNKNOWN_LOCATION, VAR_DECL, __str_id, __str_type);

    TREE_STATIC(__str_decl) = true;

    // external linkage
    TREE_PUBLIC(__str_decl) = false;

    DECL_CONTEXT(__str_decl) = NULL_TREE;
    TREE_USED(__str_decl) = true;

    // initialization to constant/read-only string 
    tree __str_init_val = build_string(len, "Global Value: %u\n");
    TREE_TYPE(__str_init_val) = __str_array_type;
    TREE_CONSTANT(__str_init_val) = false;
    TREE_STATIC(__str_init_val) = true;
    TREE_READONLY(__str_init_val) = false;

    tree adr_expr = build1(ADDR_EXPR, __str_array_ptr_type, __str_init_val);
    tree nop_expr = build1(NOP_EXPR, __str_type, adr_expr);

    DECL_INITIAL(__str_decl) = nop_expr;
    layout_decl(__str_decl, 16);
    // varpool_finalize_decl(__str_decl);

    //rest_of_decl_compilation(__str_decl, 1, 0);
    */



   /* 
    free(buf);


    tree buf_len, in_buf, out_buf;
    tree tlen = build_int_cst(integer_type_node, len);
    buf_len = build_tree_list(NULL_TREE, build_const_char_string(2, "r"));
    buf_len = chainon(NULL_TREE, build_tree_list(buf_len, tlen));
    vec_safe_push(vec_msg_len, buf_len);

    out_buf = build_tree_list(NULL_TREE, build_const_char_string(3, "=m"));
    out_buf = chainon(NULL_TREE, build_tree_list(out_buf, __str_decl));
    vec_safe_push(vec_bout, out_buf);

    in_buf = build_tree_list(NULL_TREE, build_const_char_string(3, "rm"));
    in_buf = chainon(NULL_TREE, build_tree_list(in_buf, __str_decl));
    vec_safe_push(vec_bin, in_buf);

*/

    /* lookup table */
    /*
    asprintf(&buf, "0123456789abcdef");
    len = strlen (buf) + 1;
    tree hex_xlat = build_string (len, buf);
    TREE_TYPE (hex_xlat) = build_array_type_nelts (char_type_node, len);
    TREE_READONLY (hex_xlat) = 1;
    TREE_STATIC (hex_xlat) = 1;
    hex_xlat = build_fold_addr_expr (hex_xlat);
    free(buf);   

    tree in_hex_xlat = build_tree_list(NULL_TREE, build_const_char_string(3, "rm"));
    in_hex_xlat = chainon(NULL_TREE, build_tree_list(in_hex_xlat, hex_xlat));
    vec_safe_push(vec_xlat, in_hex_xlat);

    asprintf(&buf, "xlat");
    tree xlat = get_identifier(buf);
    len = 16;//strlen (info) + 1;

    tree xlat_decl = build_decl(UNKNOWN_LOCATION, VAR_DECL, xlat, __str_type);

    TREE_STATIC(xlat_decl) = true;

    // external linkage
    TREE_PUBLIC(xlat_decl) = false;

    DECL_CONTEXT(xlat_decl) = NULL_TREE;
    TREE_USED(xlat_decl) = true;

    // initialization to constant/read-only string
    __str_init_val = build_string(len, "0123456789abcdef");
    TREE_TYPE(__str_init_val) = __str_array_type;
    TREE_CONSTANT(__str_init_val) = false;
    TREE_STATIC(__str_init_val) = true;
    TREE_READONLY(__str_init_val) = true;

    adr_expr = build1(ADDR_EXPR, __str_array_ptr_type, __str_init_val);
    nop_expr = build1(NOP_EXPR, __str_type, adr_expr);

    DECL_INITIAL(xlat_decl) = nop_expr;

    layout_decl(xlat_decl, 16);
    // rest_of_decl_compilation(xlat_decl, 1, 0);
    varpool_finalize_decl(xlat_decl);
    free(buf);

    in_hex_xlat = build_tree_list(NULL_TREE, build_const_char_string(3, "rm"));
    in_hex_xlat = chainon(NULL_TREE, build_tree_list(in_hex_xlat, xlat_decl));
    vec_safe_push(vec_xlat, in_hex_xlat);
*/



}

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
    register_callback(plugin_name, PLUGIN_START_UNIT, start_unit, NULL);
    register_callback(plugin_name, PLUGIN_FINISH_DECL, test, NULL);
    return 0;
}



