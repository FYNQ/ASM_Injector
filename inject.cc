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


static struct plugin_info callgraph_plugin_info = {
    .version    = "2020121",
    .help       = "callgraph plugin\n",
};


typedef char *char_p;


static tree gvar_tracer;

static void init_tracer_global() {
    gvar_tracer = build_decl(UNKNOWN_LOCATION, VAR_DECL, NULL_TREE,\
                                ptr_type_node);
    DECL_NAME(gvar_tracer) = create_tmp_var_name("TRACER_GLOBAL");
    DECL_ARTIFICIAL(gvar_tracer) = 1;
    TREE_STATIC(gvar_tracer) = 1;
    TREE_USED(gvar_tracer) = 1;
    TREE_PUBLIC(gvar_tracer) = 0;
    varpool_finalize_decl(gvar_tracer);
}


static tree callback_op(tree *t, int *, void *data) {
    return NULL;
}


static tree callback_stmt(gimple_stmt_iterator *gsi,
              bool *handled_all_ops,  struct walk_stmt_info *wi) {
    return NULL
}



tree build_string_constant(const char* string, int isConst) {
    size_t len = strlen(string);
//    tree index_type = build_index_type(size_int(len));
//    tree const_char_type = isConst ?  \
                            build_qualified_type(unsigned_char_type_node, \
                            TYPE_QUAL_CONST) : unsigned_char_type_node;

//    tree string_type = build_array_type(const_char_type, index_type);
    tree string_type = build_array_type_nelts (char_type_node, len);
    TYPE_STRING_FLAG(string_type) = 1;
    tree res = build_string(len, string);
    if (isConst == true)
	    TREE_READONLY(res) = 1;

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

static bool flag_instrument_functions_exclude_p (tree fndecl)
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


/* rsi ... pointer to buffer, needs to be set before calling
 * len of message
 * out could be 1(stdout) or 2 (stderr)
 * */
//gimple_seq print_str2(tree str, tree len, tree _fd) {
gimple_seq print_str2(tree str, tree len) {
    gimple g;
    gasm *asm_or_stmt;
    gimple_seq seq = NULL;
    tree len_info, fd_info;
    vec<tree, va_gc> *vec_input = NULL;
    vec<tree, va_gc> *vec_fd = NULL;
    vec<tree, va_gc> *vec_clobber = NULL;
    vec<tree, va_gc> *vec_fence = NULL;

    tree _fd = build_int_cst(long_unsigned_type_node, 1);
    /* rax syscall */
    tree syscall_nr = build_int_cst(long_unsigned_type_node, 1);
    tree syscall = build_tree_list(NULL_TREE, build_const_char_string(2, "g"));
    syscall = chainon(NULL_TREE, build_tree_list(syscall, syscall_nr));
    vec_safe_push(vec_input, syscall);

    /* edi stdout/stderr */
    tree fd_nr = build_int_cst(long_unsigned_type_node, 1);
    tree fd = build_tree_list(NULL_TREE, build_const_char_string(2, "g"));
    fd = chainon(NULL_TREE, build_tree_list(fd, fd_nr));
    vec_safe_push(vec_input, fd);

    /* edx length */
    len_info = build_tree_list(NULL_TREE, build_const_char_string(2, "g"));
    len_info = chainon(NULL_TREE, build_tree_list(len_info, len));
    vec_safe_push(vec_input, len_info);

    /* rsi addr */
    tree msg_info = build_tree_list(NULL_TREE, build_const_char_string(3, "rm"));
    msg_info = chainon(NULL_TREE, build_tree_list(msg_info, str));
    vec_safe_push(vec_input, msg_info);

    /* clobber */
    tree clobber = build_tree_list(NULL_TREE, build_const_char_string(7, "memory"));
    vec_safe_push(vec_clobber, clobber);
    clobber = build_tree_list(NULL_TREE, build_const_char_string(4, "rdi"));
    vec_safe_push(vec_clobber, clobber);
    clobber = build_tree_list(NULL_TREE, build_const_char_string(4, "rdx"));
    vec_safe_push(vec_clobber, clobber);
    clobber = build_tree_list(NULL_TREE, build_const_char_string(4, "rsi"));
    vec_safe_push(vec_clobber, clobber);
    clobber = build_tree_list(NULL_TREE, build_const_char_string(4, "rax"));
    vec_safe_push(vec_clobber, clobber);

    tree fence = build_tree_list(NULL_TREE, build_const_char_string(7, "memory"));
    vec_safe_push(vec_fence, fence);

    g = gimple_build_asm_vec("lfence", NULL, NULL, vec_fence, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);
 
    /* for length we use edx because length is unsigned int */
    g = gimple_build_asm_vec("movq %0, %%rax\n\tmovq %1, %%rdi\n\tmov %2,%%edx\n\tmovq %3,%%rsi\n\tsyscall\n\t", vec_input, NULL, vec_clobber, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("lfence", NULL, NULL, vec_fence, NULL);
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
    layout_decl(decl, 32);
	add_referenced_var(decl);
	add_local_decl(cfun, decl);

	varpool_add_new_variable(decl);
	varpool_mark_needed_node(varpool_node(decl));

	DECL_CHAIN(decl) = BLOCK_VARS(DECL_INITIAL(current_function_decl));
	BLOCK_VARS(DECL_INITIAL(current_function_decl)) = decl;

    return decl;
}



void instrument_calls() {
    basic_block bb, on_entry;
    gimple_stmt_iterator gsi;
    gimple stmt;
    gassign *assign;
    tree decl;
    char *info;

    asprintf(&info, "CALL:%s:ADDR:\n", current_function_name());
    tree len = build_int_cst(long_unsigned_type_node, strlen(info));

    /*  used later */
    tree fd = build_int_cst(long_unsigned_type_node, 1);

    tree buf_ref = create_var(unsigned_char_type_node, "buf_tracer");
    decl = add_local("buf_glib_tracer", info);
    tree expr = build_fold_addr_expr(decl);

    assign = gimple_build_assign(buf_ref, expr);
    on_entry = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
    gsi = gsi_start_bb(on_entry);
    gsi_insert_seq_before(&gsi, assign, GSI_NEW_STMT);
    free(info);

    tree charp_ptr_uint_fn_type = build_function_type_list(
                            ptr_type_node, uint32_type_node, NULL_TREE);

    tree dc_decl = build_fn_decl("dump_call_info", charp_ptr_uint_fn_type);
    FOR_EACH_BB_FN (bb, cfun) {
        for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
            stmt = gsi_stmt(gsi);

            if (gimple_code (stmt) == GIMPLE_CALL) {
                gimple call;
                gimple_seq seq = NULL;
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
                //gimple_seq_add_stmt(&seq, g);
                */
                call = gimple_build_call(dc_decl, 2, expr, len);
                gimple_call_set_lhs(call, DECL_RESULT(dc_decl));

                gimple_seq_add_stmt(&seq, call);
                //DECL_RESULT(dc_decl) = gvar_tracer;                
                gsi_insert_before(&gsi, call, GSI_SAME_STMT);
            }
        }
    }
}



void instrument_entry(){
    basic_block on_entry, on_exit;
    gimple_stmt_iterator gsi;
    gimple_seq seq = NULL;
    //const tracer_ruleset *rs = tracer_get_ruleset(fun_name);
    char *info;

    //if (rs == NULL) {
    //    return 0;
    //}

    fprintf(stderr, "## instrument_entry\n");

    asprintf(&info, "CALL:%s:ADDR:\n", current_function_name());

    tree buf_len = build_int_cst(long_unsigned_type_node, strlen(info));
    tree fd = build_int_cst(long_unsigned_type_node, 1);

    tree decl = NULL_TREE;
    tree buf_ref = create_var(unsigned_char_type_node, "buf_tracer");
    decl = add_local("buf_glib_tracer", info);
    gassign *assign;
    tree expr = build_fold_addr_expr(decl);
    assign = gimple_build_assign(buf_ref, expr);
    on_entry = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
    gsi = gsi_start_bb(on_entry);
    free(info);



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
        //print_gimple_stmt(stderr, local_stmt, 0,0);
    }
}


static void create_dump_fun() {
    basic_block on_entry;
    gimple_stmt_iterator gsi;
    gimple_seq seq = NULL;
    tree param, arg_str, arg_str_len;
    int number = 0;
    /* There should be an easier way */
    for (param = DECL_ARGUMENTS(current_function_decl); \
                    param; param = DECL_CHAIN (param)) {

        if (number == 0)
            arg_str = param;
        if (number == 1)
            arg_str_len = param;
        number++;
    }
    on_entry = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
    gsi = gsi_start_bb(on_entry);
    seq = print_str2((arg_str), (arg_str_len));
    gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);

    return;
}

static unsigned int callgraph_execute(){
    if (strncmp("dump_call_info", current_function_name(), \
                            strlen("dump_call_info")) == 0) {
        /* init global variable, used to save return 
           value of dump function 
           TODO: check if realy needed
        */
        /* We do not instrument dump_call_info function */
        //init_tracer_global();
        create_dump_fun();
        return 0;
    }
//    instrument_entry();
    instrument_calls();
//    instrument_exit();
    return 0;
}




static void start_unit(void *event_data, void *user_data){
    fprintf(stderr, "******************* START UNIT *******************\n");

    tree main_type = build_function_type_list (integer_type_node, ptr_type_node, 
                                                uint32_type_node, NULL_TREE);

    /* Function with no source location, named "main" and of the above type. */
    tree main_decl = build_decl (BUILTINS_LOCATION, FUNCTION_DECL,
                                   get_identifier ("dump_call_info"), main_type);


    tree used_attr = tree_cons(get_identifier("used"), NULL, NULL);
	decl_attributes(&main_decl, used_attr, 0);
    /* We pass a pointer to the string and its length */
    tree param_decl = NULL_TREE;
    tree str = build_decl(UNKNOWN_LOCATION, PARM_DECL,\
                        get_identifier("str"), ptr_type_node);

    DECL_ARG_TYPE(str) = ptr_type_node;
    param_decl = chainon(param_decl, str);

    tree str_len = build_decl(UNKNOWN_LOCATION, PARM_DECL,\
                        get_identifier("len"), uint32_type_node);

    DECL_ARG_TYPE(str_len) = uint32_type_node;
    param_decl = chainon(param_decl, str_len);

    /* parameter types */
    tree params = NULL_TREE;
    chainon(params, tree_cons (NULL_TREE, TREE_TYPE(str), NULL_TREE));

    /* File scope. */
    DECL_CONTEXT (main_decl) = NULL_TREE;
    /* Has a definition. */
    TREE_STATIC (main_decl) = true;
    /* External linkage. */
    TREE_PUBLIC (main_decl) = false;
    TREE_USED(main_decl) = true;
    /* Don't need anywhere to store argumnets. */
    DECL_ARGUMENTS (main_decl) = param_decl;

    /* Return value for main (). */
    /* Result variable with no name and same type as main () returns. */
    tree main_ret = build_decl (BUILTINS_LOCATION, RESULT_DECL, NULL_TREE,
                                  integer_type_node);
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
  tree bl = build_block (NULL_TREE, NULL_TREE, main_decl, NULL_TREE);
//    tree bl = build_block (decls, NULL_TREE, main_decl, NULL_TREE);
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
//    PASS_INFO(callgraph, "tsan0", 1, PASS_POS_INSERT_BEFORE);
    // Register the phase right after omplower
    struct register_pass_info pass_info;

    register_callback(plugin_name, PLUGIN_INFO, NULL, &callgraph_plugin_info);
    register_callback (plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &callgraph_pass_info);
//    register_callback(plugin_name, PLUGIN_EARLY_GIMPLE_PASSES_END, start_unit, NULL);
    register_callback(plugin_name, PLUGIN_START_UNIT, start_unit, NULL);
    return 0;
}



