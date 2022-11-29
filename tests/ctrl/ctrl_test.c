#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <osmocom/core/osmo_io.h>
#include <osmocom/core/utils.h>
#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/ctrl/control_if.h>
#include <osmo_io_internal.h>

extern struct iofd_backend_ops g_iofd_ops;

static void check_type(enum ctrl_type c)
{
	const char *t = get_value_string(ctrl_type_vals, c);
	int v = get_string_value(ctrl_type_vals, t);

	printf("ctrl type %d is %s ", c, t);
	if (v < 0)
		printf("[PARSE FAILED]\n");
	else
		printf("-> %d %s\n", v, c != v ? "FAIL" : "OK");
}

struct msgb *msgb_from_string(const char *str)
{
	struct ipaccess_head *iph;
	struct ipaccess_head_ext *ipx;
	char *str_msg;
	size_t len = strlen(str) + 1;

	struct msgb *msg = msgb_alloc(1024, str);

	iph = (void*)msgb_put(msg, sizeof(*iph));
	iph->proto = IPAC_PROTO_OSMO;

	ipx = (void*)msgb_put(msg, sizeof(*ipx));
	ipx->proto = IPAC_PROTO_EXT_CTRL;

	str_msg = (char*)msgb_put(msg, len);
	msg->l2h = (void*)str_msg;
	osmo_strlcpy(str_msg, str, len);

	iph->len = msgb_length(msg);
	return msg;
}

static void *ctx = NULL;

struct one_test {
	const char *cmd_str;
	struct ctrl_cmd expect_parsed;
	const char *reply_str;
};

void assert_same_str(const char *label, const char *expect, const char *got)
{
	if ((expect == got) || (expect && got && (strcmp(expect, got) == 0))) {
		printf("%s = '%s'\n", label, osmo_escape_str(got, -1));
		return;
	}

	printf("MISMATCH for '%s':\ngot:      %s\n", label, osmo_escape_str(got, -1));
	printf("expected: %s\n", osmo_escape_str(expect, -1));
	OSMO_ASSERT(expect == got);
}

static void assert_test(struct ctrl_handle *ctrl, struct ctrl_connection *ccon, const struct one_test *t)
{
	struct ctrl_cmd *cmd;
	bool parse_failed;
	struct msgb *msg = msgb_from_string(t->cmd_str);
	int ctx_size_was;

	printf("test: '%s'\n", osmo_escape_str(t->cmd_str, -1));
	printf("parsing:\n");

	cmd = ctrl_cmd_parse3(ctx, msg, &parse_failed);
	OSMO_ASSERT(cmd);

	if (t->expect_parsed.type != cmd->type) {
		printf("type mismatch: got %s\n", get_value_string(ctrl_type_vals, cmd->type));
		OSMO_ASSERT(t->expect_parsed.type == cmd->type);
	} else {
		printf("type = '%s'%s\n", get_value_string(ctrl_type_vals, cmd->type),
		       cmd->type != CTRL_TYPE_ERROR ? "" :
		       (parse_failed ? " (parse failure)" : " (error received)"));
	}

#define ASSERT_SAME_STR(field) \
	assert_same_str(#field, t->expect_parsed.field, cmd->field)

	ASSERT_SAME_STR(id);
	if (t->expect_parsed.type != CTRL_TYPE_ERROR) {
		ASSERT_SAME_STR(variable);
		ASSERT_SAME_STR(value);
	}
	ASSERT_SAME_STR(reply);

	talloc_free(cmd);
	msgb_free(msg);

	printf("handling:\n");

	ctx_size_was = talloc_total_size(ctx);

	msg = msgb_from_string(t->cmd_str);
	ctrl_handle_msg(ctrl, ccon, msg);

	if (ccon->iofd->tx_queue.current_length == 0) {
		if (t->reply_str) {
			printf("Got no reply, but expected \"%s\"\n", osmo_escape_str(t->reply_str, -1));
			OSMO_ASSERT(!t->reply_str);
		}
	} else {
		struct iofd_msghdr *sent_msghdr = iofd_txqueue_dequeue(ccon->iofd);
		struct msgb *sent_msg =  sent_msghdr->msg;
		OSMO_ASSERT(sent_msg);

		char *strbuf = talloc_size(sent_msg, msgb_l2len(sent_msg) + 1);
		memcpy(strbuf, msgb_l2(sent_msg), msgb_l2len(sent_msg));
		strbuf[msgb_l2len(sent_msg)] = '\0';

		printf("replied: '%s'\n", osmo_escape_str(strbuf, -1));
		OSMO_ASSERT(t->reply_str);
		OSMO_ASSERT(!strcmp(t->reply_str, strbuf));
		msgb_free(sent_msg);
		iofd_msghdr_free(sent_msghdr);
	}

	msgb_free(msg);

	if (talloc_total_size(ctx) != ctx_size_was) {
		printf("mem leak!\n");
		talloc_report_full(ctx, stdout);
		OSMO_ASSERT(false);
	}

	printf("ok\n");
}

static const struct one_test test_messages_list[] = {
	{ "GET 1 variable",
		{
			.type = CTRL_TYPE_GET,
			.id = "1",
			.variable = "variable",
		},
		"ERROR 1 Command not found",
	},
	{ "GET 1 variable\n",
		{
			.type = CTRL_TYPE_GET,
			.id = "1",
			.variable = "variable",
		},
		"ERROR 1 Command not found",

	},
	{ "GET 1 var\ni\nable",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "1",
			.reply = "GET with trailing characters",
		},
		"ERROR 1 GET with trailing characters",
	},
	{ "GET 1 var\ti\table",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "1",
			.reply = "GET variable contains invalid characters",
		},
		"ERROR 1 GET variable contains invalid characters",
	},
	{ "GET 1 var\ri\rable",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "1",
			.reply = "GET variable contains invalid characters",
		},
		"ERROR 1 GET variable contains invalid characters",
	},
	{ "GET 1 variable value",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "1",
			.reply = "GET with trailing characters",
		},
		"ERROR 1 GET with trailing characters",
	},
	{ "GET 1 variable value\n",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "1",
			.reply = "GET with trailing characters",
		},
		"ERROR 1 GET with trailing characters",
	},
	{ "GET 1 variable multiple value tokens",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "1",
			.reply = "GET with trailing characters",
		},
		"ERROR 1 GET with trailing characters",
	},
	{ "GET 1 variable multiple value tokens\n",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "1",
			.reply = "GET with trailing characters",
		},
		"ERROR 1 GET with trailing characters",
	},
	{ "SET 1 variable value",
		{
			.type = CTRL_TYPE_SET,
			.id = "1",
			.variable = "variable",
			.value = "value",
		},
		"ERROR 1 Command not found",
	},
	{ "SET 1 variable value\n",
		{
			.type = CTRL_TYPE_SET,
			.id = "1",
			.variable = "variable",
			.value = "value",
		},
		"ERROR 1 Command not found",
	},
	{ "SET weird_id variable value",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "err",
			.reply = "Invalid message ID number",
		},
		"ERROR err Invalid message ID number",
	},
	{ "SET weird_id variable value\n",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "err",
			.reply = "Invalid message ID number",
		},
		"ERROR err Invalid message ID number",
	},
	{ "SET 1 variable multiple value tokens",
		{
			.type = CTRL_TYPE_SET,
			.id = "1",
			.variable = "variable",
			.value = "multiple value tokens",
		},
		"ERROR 1 Command not found",

	},
	{ "SET 1 variable multiple value tokens\n",
		{
			.type = CTRL_TYPE_SET,
			.id = "1",
			.variable = "variable",
			.value = "multiple value tokens",
		},
		"ERROR 1 Command not found",

	},
	{ "SET 1 variable value_with_trailing_spaces  ",
		{
			.type = CTRL_TYPE_SET,
			.id = "1",
			.variable = "variable",
			.value = "value_with_trailing_spaces  ",
		},
		"ERROR 1 Command not found",
	},
	{ "SET 1 variable value_with_trailing_spaces  \n",
		{
			.type = CTRL_TYPE_SET,
			.id = "1",
			.variable = "variable",
			.value = "value_with_trailing_spaces  ",
		},
		"ERROR 1 Command not found",
	},
	{ "SET \n special_char_id value",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "err",
			.reply = "Invalid message ID number",
		},
		"ERROR err Invalid message ID number",
	},
	{ "SET \t special_char_id value",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "err",
			.reply = "Invalid message ID number",
		},
		"ERROR err Invalid message ID number",
	},
	{ "GET_REPLY 1 variable OK",
		{
			.type = CTRL_TYPE_GET_REPLY,
			.id = "1",
			.variable = "variable",
			.reply = "OK",
		},
	},
	{ "SET_REPLY 1 variable OK",
		{
			.type = CTRL_TYPE_SET_REPLY,
			.id = "1",
			.variable = "variable",
			.reply = "OK",
		},
	},
	{ "ERROR 1 some error message",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "1",
			.reply = "some error message",
		},
	},
	{ "ERROR err some error message",
		{
			.type = CTRL_TYPE_ERROR,
			.id = "err",
			.reply = "some error message",
		},
	},
};

static void test_messages(void)
{
	struct ctrl_handle *ctrl;
	struct ctrl_connection *ccon;
	int i;

	ctrl = ctrl_handle_alloc2(ctx, NULL, NULL, 0);
	ccon = talloc_zero(ctx, struct ctrl_connection);

	for (i = 0; i < ARRAY_SIZE(test_messages_list); i++) {
		ccon->iofd = osmo_iofd_setup(ccon, -1, "iofd test", OSMO_IO_FD_MODE_READ_WRITE, NULL, ccon);
		assert_test(ctrl, ccon, &test_messages_list[i]);
		osmo_iofd_close(ccon->iofd);
	}

	talloc_free(ccon);
	talloc_free(ctrl);
}

CTRL_CMD_DEFINE(test_defer, "test-defer");
static void ctrl_test_defer_cb(void *data)
{
	struct ctrl_cmd_def *cd = data;
	struct ctrl_cmd *cmd = cd->cmd;
	static int i = 0;
	printf("%s called\n", __func__);

	if (ctrl_cmd_def_is_zombie(cd)) {
		printf("Is Zombie\n");
		return;
	}

	cmd->reply = talloc_asprintf(cmd, "Test Defer #%d", i++);

	ctrl_cmd_def_send(cd);
	return;
}

static struct ctrl_cmd_def *test_defer_cd = NULL;
static int get_test_defer(struct ctrl_cmd *cmd, void *data)
{
	void *ctx = cmd->node;
	printf("%s called\n", __func__);

	test_defer_cd = ctrl_cmd_def_make(ctx, cmd, NULL, 10);

	return CTRL_CMD_HANDLED;
}
static int set_test_defer(struct ctrl_cmd *cmd, void *data)
{
	return CTRL_CMD_HANDLED;
}
static int verify_test_defer(struct ctrl_cmd *cmd, const char *value, void *data)
{
	return 0;
}

static void test_deferred_cmd(void)
{
	struct ctrl_handle *ctrl;
	struct ctrl_connection *ccon;
	struct msgb *msg;
	int result;
	int ctx_size_was;
	int ctx_size_before_defer;

	printf("\n%s\n", __func__);
	ctx_size_was = talloc_total_size(ctx);

	ctrl = ctrl_handle_alloc2(ctx, NULL, NULL, 0);
	ccon = talloc_zero(ctx, struct ctrl_connection);
	INIT_LLIST_HEAD(&ccon->def_cmds);
	ccon->iofd = osmo_iofd_setup(ccon, -1, "iofd test", OSMO_IO_FD_MODE_READ_WRITE, NULL, ccon);

	ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_test_defer);

	ctx_size_before_defer = talloc_total_size(ctx);

	msg = msgb_from_string("GET 123 test-defer");

	result = ctrl_handle_msg(ctrl, ccon, msg);
	printf("ctrl_handle_msg() returned %d\n", result);

	OSMO_ASSERT(result == CTRL_CMD_HANDLED);
	talloc_free(msg);

	/* Expecting a ctrl_cmd_def as well as the cmd to still be allocated */
	if (talloc_total_size(ctx) <= ctx_size_before_defer) {
		printf("deferred command apparently deallocated too soon\n");
		talloc_report_full(ctx, stdout);
		OSMO_ASSERT(false);
	}

	printf("invoking ctrl_test_defer_cb() asynchronously\n");
	ctrl_test_defer_cb(test_defer_cd);

	/* simulate sending of the reply */
	struct iofd_msghdr *msghdr = iofd_txqueue_dequeue(ccon->iofd);
	msgb_free(msghdr->msg);
	iofd_msghdr_free(msghdr);

	/* And now the deferred cmd should be cleaned up completely. */
	if (talloc_total_size(ctx) != ctx_size_before_defer) {
		printf("mem leak!\n");
		talloc_report_full(ctx, stdout);
		OSMO_ASSERT(false);
	}

	talloc_free(ccon);
	talloc_free(ctrl);

	if (talloc_total_size(ctx) != ctx_size_was) {
		printf("mem leak!\n");
		talloc_report_full(ctx, stdout);
		OSMO_ASSERT(false);
	}

	printf("success\n");
}

static struct log_info_cat test_categories[] = {
};

static struct log_info info = {
	.cat = test_categories,
	.num_cat = ARRAY_SIZE(test_categories),
};


static void iofd_dummy_x_y(struct osmo_io_fd *iofd)
{
}

int main(int argc, char **argv)
{
	/* Override the iofd backend functions */
	g_iofd_ops.close = NULL;
	g_iofd_ops.write_enable = iofd_dummy_x_y;
	g_iofd_ops.write_disable = iofd_dummy_x_y;
	g_iofd_ops.read_enable = iofd_dummy_x_y;
	g_iofd_ops.read_disable = iofd_dummy_x_y;

	ctx = talloc_named_const(NULL, 1, "ctrl_test");
	osmo_init_logging2(ctx, &info);
	msgb_talloc_ctx_init(ctx, 0);

	printf("Checking ctrl types...\n");

	check_type(CTRL_TYPE_UNKNOWN);
	check_type(CTRL_TYPE_GET);
	check_type(CTRL_TYPE_SET);
	check_type(CTRL_TYPE_GET_REPLY);
	check_type(CTRL_TYPE_SET_REPLY);
	check_type(CTRL_TYPE_TRAP);
	check_type(CTRL_TYPE_ERROR);
	check_type(64);

	test_messages();

	test_deferred_cmd();

	/* Expecting root ctx + msgb root ctx + 5 logging elements */
	if (talloc_total_blocks(ctx) != 7) {
		talloc_report_full(ctx, stdout);
		OSMO_ASSERT(false);
	}

	return 0;
}
