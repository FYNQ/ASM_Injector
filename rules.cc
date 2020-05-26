#include <yaml.h>
#include <cstdlib>
#include <cerrno>

#include <string>
#include <map>
#include <stdexcept>
#include <sstream>
#include <set>

#include "rules.h"

// for debugging and demonstration of the API
#include <iostream>

/*
 * Maximum allowed number of arguments for the target functions.
 */

using namespace std;

/*
 * Mapping:
 * 	"function_name" => rules
 * 	"struct_name@callback_field_name" => rules
 */
typedef map<string, tracer_ruleset> tracer_rule_map;
static tracer_rule_map rules;
/* ====================================================================== */

static string str_strip(const string &str)
{
	static const string ws =  " \n\r\t";

	size_t beg = str.find_first_not_of(ws);
	if (beg == string::npos)
		return string();

	size_t end = str.find_last_not_of(ws);
	return str.substr(beg, end - beg + 1);
}


/* ====================================================================== */

/* Name of the .yml file being processed - mostly, for error reporting. */
static string yml_file;

class kedr_yaml_event
{
public:
	yaml_event_t event;
	bool valid;

	~kedr_yaml_event()
	{
		if (valid)
			yaml_event_delete(&event);
	}
};

static string format_parse_error(const string &what,
				 unsigned int line, unsigned int col = 0)
{
	ostringstream err_text;

	err_text << yml_file << ":" << line;
	if (col)
		err_text  << ":" << col;
	err_text << ": error: " << what;
	return err_text.str();
}

static string format_yaml_event_error(const string &what,
				      const kedr_yaml_event &yevent)
{
	return format_parse_error(
		what,
		(unsigned int)yevent.event.start_mark.line + 1,
		(unsigned int)yevent.event.start_mark.column + 1);
}

static string format_rule_error(const string &func_name, const string &what,
				const kedr_yaml_event &yevent)
{
	ostringstream err_text;

	err_text << "\"" << func_name << "\": " << what;
	return format_yaml_event_error(err_text.str(), yevent);
}

static void get_next_event(yaml_parser_t &parser, kedr_yaml_event &yevent)
{
	if (!yaml_parser_parse(&parser, &yevent.event)) {
		throw runtime_error(format_parse_error(
			parser.problem,
			parser.problem_mark.line + 1,
			parser.problem_mark.column + 1));
	}

	yevent.valid = true;
}
/* ====================================================================== */



static void parse_rules_for_function(yaml_parser_t &parser,
				     const string &name,
				     tracer_ruleset &ruleset)
{
	kedr_yaml_event yevent;

	get_next_event(parser, yevent);
	if (yevent.event.type != YAML_MAPPING_START_EVENT) {
		throw runtime_error(format_rule_error(
			name,
			"expected start of a rule for this function",
			yevent));
	}

	while (true) {
		get_next_event(parser, yevent);

		if (yevent.event.type == YAML_MAPPING_END_EVENT)
			break;

		/*
		 * A pair of scalar events (type of handler, list of
		 * statements) is expected.
		 */
		if (yevent.event.type != YAML_SCALAR_EVENT) {
			throw runtime_error(format_rule_error(
				name,
				"expected the type of the handler (pre/post/...)",
				yevent));
		}

		string handler_type = str_strip(
			(const char *)(yevent.event.data.scalar.value));
		tracer_rule *rule;

		if (handler_type == "whitelist") {
			rule = &ruleset.whitelist;
			rule->type = TRACER_RULE_WHITELIST;
		}
		else if (handler_type == "blacklist") {
			rule = &ruleset.blacklist;
			rule->type = TRACER_RULE_BLACKLIST;
		}
		else {
			throw runtime_error(format_rule_error(
				name,
				"unknown handler type \"" + handler_type + "\"",
				yevent));
		}

		if (rule->valid) {
			throw runtime_error(format_rule_error(
				name,
				"found two or more rules for the \"" + handler_type + "\" handler",
				yevent));
		}

		/* get the "code" of the handler */
		get_next_event(parser, yevent);
		if (yevent.event.type != YAML_SCALAR_EVENT) {
			throw runtime_error(format_rule_error(
				name,
				"expected the list of statements",
				yevent));
		}
		string code = str_strip(
			(const char *)(yevent.event.data.scalar.value));
		//parse_code(code, *rule, yevent);
	}
}

static void populate_rule_map(yaml_parser_t &parser)
{
	while (true) {
		kedr_yaml_event yevent;
		get_next_event(parser, yevent);

		if (yevent.event.type == YAML_MAPPING_END_EVENT)
			break;

		if (yevent.event.type == YAML_SCALAR_EVENT) {
			string name = str_strip(
				(const char *)yevent.event.data.scalar.value);

			if (!name.size())
				throw runtime_error(format_yaml_event_error(
					"function name is empty",
					yevent));

			pair<tracer_rule_map::iterator, bool> retp;

			retp = rules.insert(make_pair(name, tracer_ruleset()));
			bool exists = !retp.second;
			if (exists)
				throw runtime_error(format_rule_error(
					name,
					"found two or more sets of rules for this function",
					yevent));

			tracer_ruleset &ruleset = retp.first->second;
			parse_rules_for_function(parser, name, ruleset);
		}
		else {
			throw runtime_error(format_yaml_event_error(
				"found no rules for the function",
				yevent));
		}
	}
}

void tracer_parse_rules(FILE *in, const char *fname)
{
	yaml_parser_t parser;
	bool done = false;

	yml_file = fname;

	yaml_parser_initialize(&parser);
	yaml_parser_set_input_file(&parser, in);

	try {
		while (!done) {
			kedr_yaml_event yevent;
			get_next_event(parser, yevent);

			switch (yevent.event.type) {
			case YAML_STREAM_START_EVENT:
			case YAML_DOCUMENT_START_EVENT:
			case YAML_DOCUMENT_END_EVENT:
				break;
			case YAML_STREAM_END_EVENT:
				done = true;
				break;
			case YAML_MAPPING_START_EVENT:
				populate_rule_map(parser);
				break;
			default:
				throw runtime_error(format_yaml_event_error(
					"expected the start of mapping {function => rules}",
					yevent));
			}
		}
	}
	catch (runtime_error &e) {
		cerr << e.what() << endl;
		yaml_parser_delete(&parser);
		exit(1);
	}

	yaml_parser_delete(&parser);
	return;
}

/*
 * Return the rule set for the given function, if present, NULL otherwise.
 */
const tracer_ruleset *tracer_get_ruleset(const std::string &func)
{
	tracer_rule_map::const_iterator it = rules.find(func);
	if (it == rules.end())
		return NULL;
	return &it->second;
}
