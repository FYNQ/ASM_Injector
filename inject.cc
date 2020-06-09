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

#include "rules.h"





using namespace std;


static char *rfile = NULL;

typedef map<string, tracer_ruleset> tracer_rule_map;
static tracer_rule_map rules;

tree global_decls = NULL_TREE;


static tree dc_decl;

/* Assert that this plugin is GPL compatible */
int plugin_is_GPL_compatible;


static struct plugin_info call_info_plugin_info = {
    .version    = "2020121",
    .help       = "Dump function function name and IP on entry and exit \n",
};


typedef char *char_p;


/*
static tree callback_op(tree *t, int *, void *data) {
    return NULL;
}


static tree callback_stmt(gimple_stmt_iterator *gsi,
              bool *handled_all_ops,  struct walk_stmt_info *wi) {
    return NULL;
}
*/


tree build_string_constant(const char* string, int isConst) {
    size_t len = strlen(string);
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


/* Let's push all registers */
gimple_seq push_stack() {
    gasm *asm_or_stmt;
    gimple_seq seq = NULL;
    gimple g;

    g = gimple_build_asm_vec("push %%r8\n\tpush %%r9\n\tpush %%r10\n\tpush %%r11\n\tpush %%r12\n\tpush %%r13\n\tpush %%r14\n\tpush %%r15\n\t", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("push %%rbx\n\tpush %%rsi\n\tpush %%rdx\n\tpush %%rdi\n\tpush %%rax\n\tpush %%rcx\n\t", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    return seq;
}


/* Pop all registers */
gimple_seq pop_stack() {
    gasm *asm_or_stmt;
    gimple_seq seq = NULL;
    gimple g;

    g = gimple_build_asm_vec("pop %%rcx\n\tpop %%rax\n\tpop %%rdi\n\tpop %%rdx\n\tpop %%rsi\n\tpop %%rbx\n\t", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("pop %%r15\n\tpop %%r14\n\tpop %%r13\n\tpop %%r12\n\tpop %%r11\n\tpop %%r10\n\tpop %%r9\n\tpop %%r8\n\t", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    return seq;
}



/* rsi ... pointer to buffer, needs to be set before calling
 * len of message
 */
gimple_seq print_str2(tree str, tree len) {
    gimple g;
    gasm *asm_or_stmt;
    gimple_seq seq = NULL;
    tree len_info;
    vec<tree, va_gc> *vec_input = NULL;
    vec<tree, va_gc> *vec_clobber = NULL;
    vec<tree, va_gc> *vec_fence = NULL;

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

    /* for length we use edx because length is unsigned int */
    g = gimple_build_asm_vec("movq %0, %%rax\n\tmovq %1, %%rdi\n\tmov %2,%%edx\n\tmovq %3,%%rsi\n\tsyscall\n\t", vec_input, NULL, vec_clobber, NULL);
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
gimple_seq print_addr(tree addr) {
    int i;
    tree clobber;
    gasm *asm_or_stmt;
    gimple_seq seq = NULL;
    gimple g;

    vec<tree, va_gc> *vec_input = NULL;
    vec<tree, va_gc> *vec_input_addr = NULL;
    vec<tree, va_gc> *vec_clobber = NULL; 

    tree taddr = build_tree_list(NULL_TREE, build_const_char_string(2, "g"));
    taddr = chainon(NULL_TREE, build_tree_list(taddr, addr));
    vec_safe_push(vec_input_addr, taddr);

    g = gimple_build_asm_vec("mov %0, %%rdi", vec_input_addr, NULL, NULL,  NULL);
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

    g = gimple_build_asm_vec("lea -16(%%rsp), %%rsi", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("xor %%eax, %%eax", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    g = gimple_build_asm_vec("mov $16, %%ecx", NULL, NULL, NULL,  NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);
 
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

        g = gimple_build_asm_vec("mov (%%rdx,%%rax, 1), %%al\n\t", NULL, NULL,
                                NULL,  NULL);
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

    /* Define clobber */
    clobber = build_tree_list(NULL_TREE, build_const_char_string(4, "rdx"));
    vec_safe_push(vec_clobber, clobber);
    clobber = build_tree_list(NULL_TREE, build_const_char_string(4, "rsi"));
    vec_safe_push(vec_clobber, clobber);
    clobber = build_tree_list(NULL_TREE, build_const_char_string(4, "rax"));
    vec_safe_push(vec_clobber, clobber);

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
    tree len = build_int_cst(long_unsigned_type_node, 16);
    tree len_info = build_tree_list(NULL_TREE, build_const_char_string(2, "g"));
    len_info = chainon(NULL_TREE, build_tree_list(len_info, len));
    vec_safe_push(vec_input, len_info);

    /* rsi addr */
    tree msg_info = build_tree_list(NULL_TREE, build_const_char_string(3, "g"));
    msg_info = chainon(NULL_TREE, build_tree_list(msg_info, addr));

    /* Make space on stack for result */
    g = gimple_build_asm_vec("sub $16,%%rsi\n\t", NULL, NULL, NULL, NULL);
    asm_or_stmt = as_a_gasm(g);
    gimple_asm_set_volatile(asm_or_stmt, true);
    gimple_seq_add_stmt(&seq, g);

    /* for length we use edx because length is unsigned int */
    g = gimple_build_asm_vec("movq %0, %%rax\n\tmovq %1, %%rdi\n\tmov %2,         %%edx\n\tsyscall\n\t", vec_input, NULL, vec_clobber, NULL);
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



/* used for adding local variable */
static tree add_local(const char *name, char *decl_init) {
    tree decl = build_decl (UNKNOWN_LOCATION, VAR_DECL,
                    get_identifier(name),
                    build_array_type(unsigned_char_type_node,
                    build_index_type(size_int(strlen(decl_init)))));
    
    TREE_ADDRESSABLE(decl) = true;
    TREE_USED(decl) = true;
    DECL_INITIAL(decl) = build_string_constant((const char*)\
                                                decl_init, false);
	DECL_CONTEXT(decl) = current_function_decl;
	DECL_ARTIFICIAL(decl) = 1;

	TREE_STATIC(decl) = 1;
	TREE_READONLY(decl) = 0;
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


/* Code for instrumenting calls does not work as we have no chance
 * to instrument indirect calls. */
void instrument_calls() {
    basic_block bb, on_entry;
    gimple_stmt_iterator gsi;
    gimple stmt;
    gassign *assign;
    tree decl;
    char *info;

    asprintf(&info, "\nCALL:%s:ADDR:", current_function_name());

    tree buf_ref = create_var(unsigned_char_type_node, "buf_tracer");
    decl = add_local("buf_glib_tracer", info);
    tree expr = build_fold_addr_expr(decl);

    assign = gimple_build_assign(buf_ref, expr);
    on_entry = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
    gsi = gsi_start_bb(on_entry);
    gsi_insert_seq_before(&gsi, assign, GSI_NEW_STMT);
    free(info);

    FOR_EACH_BB_FN (bb, cfun) {
        for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
            stmt = gsi_stmt(gsi);
            tree decl;
            if (gimple_code(stmt) == GIMPLE_CALL && 
                                        (decl = gimple_call_fndecl (stmt))) {

            }
            else if(gimple_code(stmt) == GIMPLE_CALL) {
            }
        }
    }
}


/* Instrument function exit */
void instrument_exit() {
    gimple call, g;
    basic_block on_exit;
    gimple_seq seq = NULL;
    gasm *asm_or_stmt;

    char *fun_info; //, *addr_buf;
    tree fun_info_decl; //, buf_decl;
    tree fun_info_expr; //, buf_expr;
    vec<tree, va_gc> *vec_rbp_buf = NULL; 
    edge e;
    edge_iterator ei;

    /* Interface for introducing rules not used at the moment */
    //const tracer_ruleset *rs = tracer_get_ruleset(fun_name);

    //if (rs == NULL) {
    //    return 0;
    //}

    fprintf(stderr, "## instrument_exit\n");

    /* We do not instrument or inlined functions */
    if (!(DECL_DECLARED_INLINE_P (cfun->decl))
            && !flag_instrument_functions_exclude_p (cfun->decl)
            /* TODO: Re-think this DECL_EXTERNAL statement */
            && !(DECL_EXTERNAL (cfun->decl)) ) {

//        tree buf_ref = create_var(unsigned_char_type_node, "buf_tracer3");
        /* Variable decl fun_expr contains function name string */
        asprintf(&fun_info, ":EXIT:%s\n", current_function_name());
        fun_info_decl = add_local("exit_buf_gt", fun_info);
        fun_info_expr = build_fold_addr_expr(fun_info_decl);
//        assign = gimple_build_assign(buf_ref, fun_info_expr);
        tree len = build_int_cst(long_unsigned_type_node, strlen(fun_info));
        free(fun_info);

        /* buffer to store entry address */
        tree addr_info = build_int_cst(long_unsigned_type_node, 0);
        tree tlbuf = build_tree_list(NULL_TREE,
                                    build_const_char_string(3, "=r"));
        tlbuf = chainon(NULL_TREE, build_tree_list(tlbuf, addr_info));
        vec_safe_push(vec_rbp_buf, tlbuf);

        /* function entry block */
        on_exit = EXIT_BLOCK_PTR_FOR_FN(cfun);

        FOR_EACH_EDGE(e, ei, on_exit->preds) {
            gimple_stmt_iterator gsi;
            gimple stmt;

            gsi = gsi_last_bb(e->src);
            stmt = gsi_stmt(gsi);

            /* Sanity check, just in case */
            gcc_assert(gimple_code(stmt) == GIMPLE_RETURN ||
                   gimple_call_builtin_p(stmt, BUILT_IN_RETURN));

	        tree addr_var = create_tmp_var(long_long_unsigned_type_node,
                                            "addr_rbp");
	        add_referenced_var(addr_var);
	        tree output = build_tree_list(NULL_TREE,
                                        build_const_char_string(3, "=r"));
	        output = chainon(NULL_TREE, build_tree_list(output, addr_var));
            vec<tree, va_gc> *outputs = NULL;
            vec_safe_push(outputs, output);

           /* Get RIP and save buffer */
            g = gimple_build_asm_vec("lea (%%rip), %0\n\t", NULL,
                                            outputs, NULL,  NULL);
            asm_or_stmt = as_a_gasm(g);
            gimple_asm_set_volatile(asm_or_stmt, true);
            gimple_seq_add_stmt(&seq, g);

            call = gimple_build_call(dc_decl, 3, fun_info_expr, len, addr_var);
            gimple_seq_add_stmt(&seq, call);
            gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);
        }
    }
}



void instrument_entry(){
    gimple call, g;
    basic_block on_entry;
    gimple_stmt_iterator gsi;
    gimple_seq seq = NULL;
    gasm *asm_or_stmt;
    char *fun_info; //, *addr_buf;
    tree fun_info_decl;//, buf_decl;
    tree fun_info_expr; //, buf_expr;
    vec<tree, va_gc> *vec_rbp_buf = NULL;

    /* Interface for introducing rules not used at the moment */
    //const tracer_ruleset *rs = tracer_get_ruleset(fun_name);

    //if (rs == NULL) {
    //    return 0;
    //}

    fprintf(stderr, "## instrument_entry\n");

    /* We do not instrument or inlined functions */
    if (!(DECL_DECLARED_INLINE_P (cfun->decl))
            && !flag_instrument_functions_exclude_p (cfun->decl)
            /* TODO: Re-think this DECL_EXTERNAL statement */
            && !(DECL_EXTERNAL (cfun->decl)) ) {

        gassign *assign;
        tree buf_ref = create_var(unsigned_char_type_node, "buf_tracer2");
        /* Variable decl fun_expr contains function name string */
        asprintf(&fun_info, ":ENTRY:%s:\n", current_function_name());
        fun_info_decl = add_local("entry_buf_gt", fun_info);
        fun_info_expr = build_fold_addr_expr(fun_info_decl);
        assign = gimple_build_assign(buf_ref, fun_info_expr);
        tree len = build_int_cst(long_unsigned_type_node, strlen(fun_info));
        free(fun_info);

        /* buffer to store entry address */
        tree addr_info = build_int_cst(long_unsigned_type_node, 0);
        tree tlbuf = build_tree_list(NULL_TREE, 
                                    build_const_char_string(3, "=r"));
        tlbuf = chainon(NULL_TREE, build_tree_list(tlbuf, addr_info));
        vec_safe_push(vec_rbp_buf, tlbuf);

        /* function entry block */
        on_entry = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
        gsi = gsi_start_bb(on_entry);

        gsi_insert_seq_before(&gsi, assign, GSI_NEW_STMT);

        /* Get RIP */
        g = gimple_build_asm_vec("lea (%%rip), %%rcx\n\t", NULL,
                NULL, NULL,  NULL);
        asm_or_stmt = as_a_gasm(g);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gimple_seq_add_stmt(&seq, g);

	    tree addr_var = create_tmp_var(long_long_unsigned_type_node, "addr_rbp");
	    add_referenced_var(addr_var);
	    tree output = build_tree_list(NULL_TREE,
                                        build_const_char_string(3, "=r"));
	    output = chainon(NULL_TREE, build_tree_list(output, addr_var));
        vec<tree, va_gc> *outputs = NULL;
        vec_safe_push(outputs, output);

        /* save to buffer */
        g = gimple_build_asm_vec("movq %%rcx, %0\n\t", NULL, outputs,
                                    NULL,  NULL);
        asm_or_stmt = as_a_gasm(g);
        gimple_asm_set_volatile(asm_or_stmt, true);
        gimple_seq_add_stmt(&seq, g);

        call = gimple_build_call(dc_decl, 3, fun_info_expr, len, addr_var);
        gimple_seq_add_stmt(&seq, call);

        gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);
    }
}

/* Add code to dump_call_info funcion */
static void create_dump_fun() {
    basic_block on_entry;
    gimple_stmt_iterator gsi;
    gimple_seq seq = NULL;
    tree param, arg_str, arg_str_len, addr;
    int number = 0;
    /* There should be an easier way */
    for (param = DECL_ARGUMENTS(current_function_decl); \
                    param; param = DECL_CHAIN (param)) {

        if (number == 0)
            arg_str = param;
        if (number == 1)
            arg_str_len = param;
        if (number == 2)
            addr = param;
        number++;
    }

    on_entry = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
    gsi = gsi_start_bb(on_entry);

    seq = print_str2(arg_str, arg_str_len);
    gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);

    seq = pop_stack();
    gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);

    seq = print_addr(addr);
    gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);

    seq = push_stack();
    gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);


    return;
}

static unsigned int fun_info_execute(){
    if (strncmp("dump_call_info", current_function_name(), \
                            strlen("dump_call_info")) == 0) {
        /* We do not instrument dump_call_info function */
        create_dump_fun();
        return 0;
    }
    instrument_entry();
   //instrument_calls();
    instrument_exit();
    return 0;
}



/* Inspired/taken from https://cpjsmith.uk/gccfe */
static void start_unit(void *event_data, void *user_data){
    fprintf(stderr, "******************* START UNIT *******************\n");

    tree main_type = build_function_type_list (integer_type_node, ptr_type_node, 
                                                uint32_type_node,
                                                long_long_unsigned_type_node,
                                                NULL_TREE);

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

    tree addr = build_decl(UNKNOWN_LOCATION, PARM_DECL,\
                        get_identifier("addr"), long_long_unsigned_type_node);

    DECL_ARG_TYPE(addr) = long_long_unsigned_type_node;
    param_decl = chainon(param_decl, addr);


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

    /* Block to represent the scope of local variables. */
    tree bl = build_block (NULL_TREE, NULL_TREE, main_decl, NULL_TREE);
    DECL_INITIAL (main_decl) = bl;
    TREE_USED (bl) = true;

    /* The bind expression contains the statements to execute. */
    tree bind = build3 (BIND_EXPR, void_type_node, BLOCK_VARS (bl), \
                                NULL_TREE, bl);
    /* Don't optimise it away. */
    TREE_SIDE_EFFECTS (bind) = true;

    /* List of statements in the main () function. */
    tree main_stmts = alloc_stmt_list ();


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
    /* Lets build the function declaration for the dump call */
    tree charp_ptr_uint_fn_type = build_function_type_list(
                                ptr_type_node, uint32_type_node,
                                long_long_unsigned_type_node, NULL_TREE);

    dc_decl = build_fn_decl("dump_call_info", charp_ptr_uint_fn_type);

}


#define PASS_NAME fun_info

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

    PASS_INFO(fun_info, "ssa", 1, PASS_POS_INSERT_AFTER);

    register_callback(plugin_name, PLUGIN_INFO, NULL, &call_info_plugin_info);
    register_callback (plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL,
                                &fun_info_pass_info);
    register_callback(plugin_name, PLUGIN_START_UNIT, start_unit, NULL);
    return 0;
}



