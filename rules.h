#ifndef _TRACER_RULE_PARSER_H
#define _TRACER_RULE_PARSER_H

#include <vector>
#include <string>
#include <set>

/*
 * A single statement.
 */


enum tracer_rule_type
{
	TRACER_RULE_WHITELIST, /* applied on entry to the function */
	TRACER_RULE_BLACKLIST,  /* applied right before the function returns */
};

/*
 * A rule for instrumentation of some code construct.
 */
struct tracer_rule
{
	/* If false, this rule is empty or invalid and cannot be used. */
	bool valid;

	enum tracer_rule_type type;

	/* The local variables to be added. */
//	std::set<std::string> locals;

	/* The list of statements in this rule. */
//	std::vector<kedr_i13n_statement> stmts;

	/* Line number for this rule in the rules file. */
//	unsigned int lineno;
};

/*
 * The rules for the function calls (pre, post) and for the entry/exit
 * handling of callbacks.
 */
//struct kedr_i13n_ruleset
struct tracer_ruleset
{
	tracer_rule blacklist;
	tracer_rule whitelist;
};

void tracer_parse_rules(FILE *in, const char *fname);
const tracer_ruleset *tracer_get_ruleset(const std::string &func);

#endif /* _TRACER_RULE_PARSER_H */
