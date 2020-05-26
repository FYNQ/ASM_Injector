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

tree global_decls = NULL_TREE;



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


tree build_string_constant(const char* string, int isConst) {
    size_t len = strlen(string);
    tree index_type = build_index_type(size_int(len));
    tree const_char_type = isConst ?  \
                            build_qualified_type(unsigned_char_type_node, \
                            TYPE_QUAL_CONST) : unsigned_char_type_node;

//    tree string_type = build_array_type(const_char_type, index_type);
    tree string_type = build_array_type_nelts (char_type_node, len + 1);
    TYPE_STRING_FLAG(string_type) = 1;
    tree res = build_string(len + 1, string);
    TREE_TYPE(res) = string_type;

  return res;
}

static tree create_var(tree type, const char *name)
{
    tree var;

    var = create_tmp_var(type, name);
    add_referenced_var(var);
    mark_sym_for_renaming(var);

    return var;
}

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

    vec<tree, va_gc> *vec_fence = NULL;
    tree fence = build_tree_list(NULL_TREE, build_const_char_string(7, "memory"));
    vec_safe_push(vec_fence, fence);

    g = gimple_build_asm_vec("mfence", NULL, NULL, vec_fence, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
//    gimple_seq_add_stmt(&seq, g);




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

    g = gimple_build_asm_vec("pop %%r8", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("pop %%r9", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("pop %%r10", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("pop %%r11", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("pop %%r12", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("pop %%r13", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("pop %%r14", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("pop %%r15", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);



    g = gimple_build_asm_vec("sub $-0x1000,%%rsp", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
//    gimple_seq_add_stmt(&seq, g);
    return seq;
}



gimple_seq push_stack() {
    gasm *asm_or_stmt;
    gimple_seq seq = NULL;
    gimple g;


    g = gimple_build_asm_vec("add $-0x1000,%%rsp", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
//    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("push %%r15", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);


    g = gimple_build_asm_vec("push %%r14", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);


    g = gimple_build_asm_vec("push %%r13", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);


    g = gimple_build_asm_vec("push %%r12", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);


    g = gimple_build_asm_vec("push %%r11", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("push %%r10", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("push %%r9", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("push %%r8", NULL, NULL, NULL, NULL);
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

    g = gimple_build_asm_vec("push %%rbx", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("push %%rsp", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);


    vec<tree, va_gc> *vec_fence = NULL;
    tree fence = build_tree_list(NULL_TREE, build_const_char_string(7, "memory"));
    vec_safe_push(vec_fence, fence);

    g = gimple_build_asm_vec("mfence", NULL, NULL, vec_fence, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    return seq;
}




/* rsi ... pointer to buffer, needs to be set before calling
 * len of message
 * out could be 1(stdout) or 2 (stderr)
 * */
gimple_seq print_str2(tree str, tree len, tree fd) {
    gimple g;
    gasm *asm_or_stmt;
    gimple_seq seq = NULL;
    tree len_info, fd_info;
    vec<tree, va_gc> *vec_fd = NULL;
    vec<tree, va_gc> *vec_msg = NULL;
    vec<tree, va_gc> *vec_msg_len = NULL;

    fd_info = build_tree_list(NULL_TREE, build_const_char_string(2, "r"));
    fd_info = chainon(NULL_TREE, build_tree_list(fd_info, fd));
    vec_safe_push(vec_fd, fd_info);

    len_info = build_tree_list(NULL_TREE, build_const_char_string(2, "r"));
    len_info = chainon(NULL_TREE, build_tree_list(len_info, len));
    vec_safe_push(vec_msg_len, len_info);

    tree out_buf = build_tree_list(NULL_TREE, build_const_char_string(3, "rm"));
    out_buf = chainon(NULL_TREE, build_tree_list(out_buf, str));
    vec_safe_push(vec_msg, out_buf);
    // KKK



    g = gimple_build_asm_vec("movq %0, %%rsi", vec_msg, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("movq %0, %%rdx", vec_msg_len, NULL, NULL, NULL);
    //g = gimple_build_asm_vec("mov $5, %%edx", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    //g = gimple_build_asm_vec("mov $1, %%rdi", NULL, NULL, NULL, NULL);
    //g = gimple_build_asm_vec("movq %0, %%rdi", vec_fd, NULL, NULL, NULL);
    //g = gimple_build_asm_vec("movq $1, %%eax", NULL, NULL, NULL, NULL);
    //asm_or_stmt = as_a_gasm(g);
    //gimple_asm_set_volatile(asm_or_stmt, true);
    //gimple_seq_add_stmt(&seq, g);

    /* set output and syscall number */
    g = gimple_build_asm_vec("mov $1, %%rax", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("mov %%rax, %%rdi", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
//    gimple_seq_add_stmt(&seq, g);



    g = gimple_build_asm_vec("syscall", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);
    

    return seq;
}


/* 
 * rdi ... location of register to be printed 
 * rdx ... translation table location on stack
 * rsi ... output buffer on stack again
 */
gimple_seq print_reg() {
    gasm *asm_or_stmt;
    gimple_seq seq = NULL;
    gimple_seq sseq = NULL;
    gimple g;

    g = gimple_build_asm_vec("lea -16(%%rsp), %%rsi", NULL, NULL, NULL,  NULL);
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


gimple_seq print_ret_addr() {
    gimple g;
    gasm *asm_or_stmt;
    gimple_seq seq = NULL;
    gimple_seq sseq = NULL;

    /* load base pointer to reg */
    g = gimple_build_asm_vec("mov %%rbp, %%rcx\n\t", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    /* get retrun address from stack*/
    g = gimple_build_asm_vec("add $8, %%rcx\n\t", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);


    g = gimple_build_asm_vec("movq (%%rcx), %%rdi", NULL, NULL, NULL,  NULL);
    //g = gimple_build_asm_vec("movq $0xdeadbeefdeadbeef, %%rdi", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    sseq = print_reg();
    gimple_seq_add_seq(&seq, sseq);
    //XXX
    return seq;
}
static tree jpanic;
static void init_jpanic_global(void)
{
    if (jpanic == NULL_TREE)
    {
        jpanic = build_decl(BUILTINS_LOCATION, VAR_DECL, NULL, integer_type_node);
        jpanic = make_ssa_name(jpanic, gimple_build_nop());
        DECL_NAME(jpanic) = create_tmp_var_name("__el_jpanic");
        TREE_STATIC(jpanic) = 1;
        DECL_ARTIFICIAL(jpanic) = 1;
        DECL_REGISTER(jpanic) = 1;
    }
}

static tree intArray; 


static tree add_local(char *name, char *decl_init) {
    tree decl = build_decl (UNKNOWN_LOCATION, VAR_DECL,
                    get_identifier(name),
                    build_array_type(unsigned_char_type_node,
                    build_index_type(size_int(strlen(decl_init)))));
    
    TREE_ADDRESSABLE(decl) = true;
    TREE_USED(decl) = true;
    DECL_INITIAL(decl) = build_string_constant((const char*)\
                                                decl_init, false);
    location_t loc;
    loc = DECL_SOURCE_LOCATION(current_function_decl);
	DECL_CONTEXT(decl) = current_function_decl;
	DECL_ARTIFICIAL(decl) = 1;

	TREE_STATIC(decl) = 1;
	TREE_READONLY(decl) = 1;
	TREE_ADDRESSABLE(decl) = 1;
	TREE_USED(decl) = 1;
    layout_decl(decl, 16);
//    debug_tree(decl);
	add_referenced_var(decl);
	add_local_decl(cfun, decl);

	varpool_add_new_variable(decl);
	varpool_mark_needed_node(varpool_node(decl));

	DECL_CHAIN(decl) = BLOCK_VARS(DECL_INITIAL(current_function_decl));
	BLOCK_VARS(DECL_INITIAL(current_function_decl)) = decl;

    return decl;
}



void instrument_calls() {
    basic_block bb;
    gimple_stmt_iterator gsi;
    gimple_seq sseq = NULL;
    gimple_seq seq = NULL;
    gimple g, local_stmt;
    gasm *asm_or_stmt;       
    gimple stmt;
    char *fun_name;
    char *info;
    char out_buffer[128];
    char *tmp;
    vec<tree, va_gc> *vec_addr = NULL;

    asprintf(&tmp, "\n");
    basic_block on_entry;

    tree dec_node;

    vec<tree, va_gc> *vec_fence = NULL;
    tree fence = build_tree_list(NULL_TREE, build_const_char_string(7, "memory"));
    vec_safe_push(vec_fence, fence);


    FOR_EACH_BB_FN (bb, cfun) {

//        asprintf(&info, "CALL:%s:ADDR:", \
//                        IDENTIFIER_POINTER(DECL_NAME(cfun->decl)));
        asprintf(&info, "CALL:%s:ADDR:", "0x0000000000000000000000000\n");


        tree buf_len = build_int_cst(long_unsigned_type_node, strlen(info) + 1);
        tree fd = build_int_cst(long_unsigned_type_node, 1);

        tree decl = NULL_TREE;
        tree buf_ref = create_var(unsigned_char_type_node, "buf_tracer");
        decl = add_local("buf", info);
        gassign *assign;
        tree expr = build_fold_addr_expr(decl);
//        debug_tree(expr);
        assign = gimple_build_assign(buf_ref, expr);
        on_entry = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
        gsi = gsi_start_bb(on_entry);
        gsi_insert_seq_before(&gsi, assign, GSI_NEW_STMT);


        for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
            stmt = gsi_stmt(gsi);

            if (gimple_code (stmt) == GIMPLE_CALL) {
                seq = NULL;


    g = gimple_build_asm_vec("mfence", NULL, NULL, vec_fence, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);


                sseq = push_stack();
                gimple_seq_add_seq(&seq, sseq);

                vec_addr = NULL;
	            tree callee = gimple_call_fn(as_a <gcall *>(stmt));
	            tree output = build_tree_list(NULL_TREE, \
                                        build_const_char_string(3, "r"));
	            output = chainon(NULL_TREE, build_tree_list(output, callee));
                vec_safe_push(vec_addr, output);
                g = gimple_build_asm_vec("mov %0, %%rdi", vec_addr, \
                                                NULL, NULL,  NULL);
                asm_or_stmt = as_a_gasm(g);
                gimple_asm_set_volatile(asm_or_stmt, true);
                //gimple_seq_add_stmt(&seq, g);

                //sseq = print_reg();
                //gimple_seq_add_seq(&seq, sseq);


                //debug_tree(buf_ref);
                //tree t = build_fold_addr_expr (buf_decl);
                sseq = print_str2(expr, buf_len, fd);
                gimple_seq_add_seq(&seq, sseq);





                //fprintf(stderr, "## instrument_calls\n");
                //print_gimple_stmt(stderr, stmt,0,0);



                //gimple_seq_add_seq(&seq, stmt);

                //sseq = load_str(fun_name, 1);
                //gimple_seq_add_seq(&seq, sseq);

                //sseq = print_str(strlen(fun_name), 1);
                //gimple_seq_add_seq(&seq, sseq);


/*
                vec_addr = NULL;
	            tree callee = gimple_call_fn(as_a <gcall *>(stmt));
	            tree output = build_tree_list(NULL_TREE, \
                                        build_const_char_string(3, "r"));
	            output = chainon(NULL_TREE, build_tree_list(output, callee));
                vec_safe_push(vec_addr, output);
                g = gimple_build_asm_vec("mov %0, %%rdi", vec_addr, \
                                                NULL, NULL,  NULL);
                asm_or_stmt = as_a_gasm(g);
                gimple_asm_set_volatile(asm_or_stmt, true);
                gimple_seq_add_stmt(&seq, g);
                sseq = print_reg();
                gimple_seq_add_seq(&seq, sseq);
                sseq = load_str(tmp);
                gimple_seq_add_seq(&seq, sseq);
                sseq = print_str(strlen(tmp), 1);
                gimple_seq_add_seq(&seq, sseq);
*/

                sseq = pop_stack();
                gimple_seq_add_seq(&seq, sseq);
    g = gimple_build_asm_vec("mfence", NULL, NULL, vec_fence, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

                gsi_insert_seq_before(&gsi, seq, GSI_SAME_STMT);

            }
        }

        free(info);
    }
    free(tmp);
}



void instrument_entry(){
    basic_block on_entry, on_exit;
    gimple_stmt_iterator gsi;
    gimple_seq seq = NULL;
    expanded_location xloc;
    //const tracer_ruleset *rs = tracer_get_ruleset(fun_name);
    char *sep;
    char *info;
    char *arrow;
    asprintf(&arrow, "---->");
    asprintf(&sep, ":");

    static bool initted;

    if (!initted)
    {
        init_jpanic_global();
        initted = true;
    }


    //if (rs == NULL) {
    //    return 0;
    //}

    fprintf(stderr, "## instrument_entry\n");
    xloc = expand_location(DECL_SOURCE_LOCATION(cfun->decl));
    const char *fname = DECL_SOURCE_FILE(cfun->decl);
    printf("## file: %s\n## function: %s\n", fname, current_function_name());
    char *fun_name;
    asprintf(&info, "ENTRY:%s:ADDR:", IDENTIFIER_POINTER(DECL_NAME(cfun->decl)));
    
    /*
    used for exit instrumentation
    gsi = gsi_last_bb(on_entry);
    */

    if (!(DECL_DECLARED_INLINE_P (cfun->decl))
            && !flag_instrument_functions_exclude_p (cfun->decl)
            && !(DECL_EXTERNAL (cfun->decl)) ) {

        tree buf_ref = create_var(unsigned_char_type_node, "buf_tracer");
        tree buf_decl;
        //gimple local_stmt = add_local("buf", info, buf_decl, buf_ref);
        //debug_tree(DECL_ARGUMENTS(current_function_decl));
        on_entry = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
        gsi = gsi_start_bb(on_entry);
        //gsi_insert_before(&gsi, local_stmt, GSI_NEW_STMT);
        //print_gimple_stmt(stderr, local_stmt, 0,0);


        /* Pop stack*/
        seq = pop_stack();
        gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);

        seq = print_ret_addr();
        gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);


        //seq = print_str(strlen(fun_name), 2);
        //gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);
        //seq = load_str(fun_name, 1);
        //gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);

        /* Push stack*/
        seq = push_stack();
        gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);
    }
    
    free(sep);
    free(arrow);
    //free(fun_name);
}

static unsigned int callgraph_execute(){
//    instrument_entry();
    instrument_calls();

//    instrument_exit();
    return 0;
}


#define PREF_SYM        "__ksymtab_"


static void start_unit(void *event_data, void *user_data){
    tree main_type = build_function_type_list (integer_type_node, NULL_TREE);
    /* Function with no source location, named "main" and of the above type. */
    tree main_decl = build_decl (BUILTINS_LOCATION, FUNCTION_DECL,
                                   get_identifier ("testxx"), main_type);

    /* File scope. */
    DECL_CONTEXT (main_decl) = NULL_TREE;
    /* Has a definition. */
    TREE_STATIC (main_decl) = true;
    /* External linkage. */
    TREE_PUBLIC (main_decl) = false;
    TREE_USED(main_decl) = true;
    /* Don't need anywhere to store argumnets. */
    DECL_ARGUMENTS (main_decl) = NULL_TREE;

    /* Return value for main (). */
    /* Result variable with no name and same type as main () returns. */
    tree main_ret = build_decl (BUILTINS_LOCATION, RESULT_DECL, NULL_TREE,
                                  TREE_TYPE (main_type));
    /* Scoped within the main function. */
    DECL_CONTEXT (main_ret) = main_decl;
    /* Generated by the compiler. */
    DECL_ARTIFICIAL (main_ret) = true;
    /* No debugging symbol. */
    DECL_IGNORED_P (main_ret) = true;

    /* The result of the function is the above value. */
    DECL_RESULT (main_decl) = main_ret;

    tree decls = NULL_TREE;

    // Declare a variables
    tree intArray = build_decl (UNKNOWN_LOCATION, VAR_DECL, \
            get_identifier("array"), build_array_type(unsigned_char_type_node, \
            build_index_type(size_int(9))));
    TREE_ADDRESSABLE(intArray) = true;
    TREE_USED(intArray) = true;

    TREE_CHAIN( intArray ) = decls;
    decls = intArray;

    tree variable_pk = build_decl (UNKNOWN_LOCATION, VAR_DECL, get_identifier("pk"), build_pointer_type(integer_type_node));
    TREE_ADDRESSABLE(variable_pk) = true;
    TREE_USED(variable_pk) = true;

    TREE_CHAIN( variable_pk ) = decls;
    decls = variable_pk;

    tree variable_pi = build_decl (UNKNOWN_LOCATION, VAR_DECL, \
            get_identifier("pi"), build_pointer_type(integer_type_node));
    TREE_ADDRESSABLE(variable_pi) = true;
    TREE_USED(variable_pi) = true;

    TREE_CHAIN( variable_pi ) = decls;
    decls = variable_pi;


    tree variable_i = build_decl (UNKNOWN_LOCATION, VAR_DECL, get_identifier("i"),   integer_type_node);
    TREE_ADDRESSABLE(variable_i) = true;
    TREE_USED(variable_i) = true;

    TREE_CHAIN( variable_i ) = decls;
    decls = variable_i;

    DECL_INITIAL(intArray) = build_string_constant((const char*) "abcd efgh", false);
    DECL_INITIAL(variable_pi) = build1(ADDR_EXPR,\
            build_pointer_type(TREE_TYPE(variable_i)), variable_i);
  /* Block to represent the scope of local variables. */
  //tree bl = build_block (NULL_TREE, NULL_TREE, main_decl, NULL_TREE);
    tree bl = build_block (decls, NULL_TREE, main_decl, NULL_TREE);
    DECL_INITIAL (main_decl) = bl;
    TREE_USED (bl) = true;

    /* The bind expression contains the statements to execute. */
    tree bind = build3 (BIND_EXPR, void_type_node, BLOCK_VARS (bl), \
                                NULL_TREE, bl);
    /* Don't optimise it away. */
    TREE_SIDE_EFFECTS (bind) = true;

    /* List of statements in the main () function. */
    tree main_stmts = alloc_stmt_list ();


    append_to_statement_list(build1(DECL_EXPR, void_type_node, variable_i),\
                                    &main_stmts);



    append_to_statement_list(build1(DECL_EXPR, void_type_node, variable_pi),\
                                    &main_stmts);



    append_to_statement_list(build1(DECL_EXPR, void_type_node, intArray),\
                                    &main_stmts);



    /* Build the puts () function declaration. */
    /* Function type which returns int with unspecified parameters. */
    tree puts_type = build_function_type (integer_type_node, NULL_TREE);
    /* Function named "puts" of that type. */
    tree puts_decl = build_decl (BUILTINS_LOCATION, FUNCTION_DECL,
                               get_identifier ("puts"), puts_type);
    /* Only a declaration, no definition. */
    DECL_EXTERNAL (puts_decl) = true;
    /* External linkage. */
    TREE_PUBLIC (puts_decl) = true;
    /* puts("..."); */
    /* Expression which calls puts () with 1 argument which is a string literal
     * containing the source file data. */
    /* tree call_puts = build_call_expr (puts_decl, 1,
                                    build_string_literal (
                                        0,
                                        0));
       append_to_statement_list (call_puts, &main_stmts);
    */
    /* return 0; */
    /* Assign 0 to the return value. */
    tree main_set_ret = build2 (MODIFY_EXPR, TREE_TYPE (main_ret), main_ret,
                                  build_int_cst (integer_type_node, 0));
    /* Perform the assignment and return from the function. */
    tree main_ret_expr = build1 (RETURN_EXPR, void_type_node, main_set_ret);
    append_to_statement_list (main_ret_expr, &main_stmts);




    /* Make the bind contain the statements. */
    BIND_EXPR_BODY (bind) = main_stmts;
    /* Set main to use the statements in bind. */
    DECL_SAVED_TREE (main_decl) = bind;

    /* Add the main function to the list of global declarations. */
    global_decls = chainon (main_decl, global_decls);

    /* Prepare declarations for middle-end. */
    for (tree t = global_decls; t; t = TREE_CHAIN (t)) {
        gimplify_function_tree (t);
        cgraph_node::finalize_function(t, false);
    }
}

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

    PASS_INFO(callgraph, "ssa", 1, PASS_POS_INSERT_AFTER);
//    PASS_INFO(callgraph, "ssa", 1, PASS_POS_INSERT_BEFORE);
    // Register the phase right after omplower
    struct register_pass_info pass_info;

    register_callback(plugin_name, PLUGIN_INFO, NULL, &callgraph_plugin_info);
    register_callback (plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &callgraph_pass_info);
//    register_callback(plugin_name, PLUGIN_START_UNIT, start_unit, NULL);
    register_callback(plugin_name, PLUGIN_FINISH_DECL, test, NULL);
    return 0;
}



