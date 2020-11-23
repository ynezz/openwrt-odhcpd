#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include "dhcpv4.h"

static bool _dhcpv4_parse_options(void *data, size_t len, struct interface *iface, struct dhcpv4_message *req, uint32_t *reqaddr, uint8_t *reqmsg,
		uint32_t *leasetime, char *hostname, size_t *hostname_len,
		char *reqopts, size_t *reqopts_len, bool *accept_fr_nonce)
{
	uint8_t *start = &req->options[4];
	uint8_t *end = ((uint8_t*)data) + len;
	struct dhcpv4_option *opt;

	dhcpv4_for_each_option(start, end, opt) {
		if (opt->type == DHCPV4_OPT_MESSAGE && opt->len == 1)
			*reqmsg = opt->data[0];
		else if (opt->type == DHCPV4_OPT_REQOPTS && opt->len > 0) {
			*reqopts_len = opt->len;
			memcpy(reqopts, opt->data, *reqopts_len);
			reqopts[*reqopts_len] = 0;
		} else if (opt->type == DHCPV4_OPT_HOSTNAME && opt->len > 0) {
			*hostname_len = opt->len;
			memcpy(hostname, opt->data, *hostname_len);
			hostname[*hostname_len] = 0;
		} else if (opt->type == DHCPV4_OPT_IPADDRESS && opt->len == 4)
			memcpy(reqaddr, opt->data, 4);
		else if (opt->type == DHCPV4_OPT_SERVERID && opt->len == 4) {
			if (memcmp(opt->data, &iface->dhcpv4_local, 4))
				return false;
		} else if (iface->filter_class && opt->type == DHCPV4_OPT_USER_CLASS) {
			uint8_t *c = opt->data, *cend = &opt->data[opt->len];
			for (; c < cend && &c[*c] < cend; c = &c[1 + *c]) {
				size_t elen = strlen(iface->filter_class);
				if (*c == elen && !memcmp(&c[1], iface->filter_class, elen))
					return false; // Ignore from homenet
			}
		} else if (opt->type == DHCPV4_OPT_LEASETIME && opt->len == 4)
			memcpy(leasetime, opt->data, 4);
		else if (opt->type == DHCPV4_OPT_FORCERENEW_NONCE_CAPABLE && opt->len > 0) {
			for (uint8_t i = 0; i < opt->len; i++) {
				if (opt->data[i] == 1) {
					*accept_fr_nonce = true;
					break;
				}
			}

		}
	}

	if (*reqmsg != DHCPV4_MSG_DISCOVER && *reqmsg != DHCPV4_MSG_REQUEST &&
	    *reqmsg != DHCPV4_MSG_INFORM && *reqmsg != DHCPV4_MSG_DECLINE &&
	    *reqmsg != DHCPV4_MSG_RELEASE)
		return false;

	fprintf(stderr, "parsed!\n");
	return true;
}

static void fuzz_handle_dhcpv4(void *data, size_t len)
{
	uint32_t leasetime = 0;
	uint32_t reqaddr = INADDR_ANY;
	struct interface iface = { 0 };
	struct dhcpv4_message *req = data;
	uint8_t reqmsg = DHCPV4_MSG_REQUEST;
	size_t limit = offsetof(struct dhcpv4_message, options);

	fprintf(stderr, "limit: %zu len: %zu\n", limit, len);

	if (len < limit || req->op != DHCPV4_BOOTREQUEST || req->hlen != 6)
		return;

	struct dhcpv4_message reply = {
		.op = DHCPV4_BOOTREPLY,
		.htype = req->htype,
		.hlen = req->hlen,
		.hops = 0,
		.xid = req->xid,
		.secs = 0,
		.flags = req->flags,
		.ciaddr = {INADDR_ANY},
		.giaddr = req->giaddr,
		.siaddr = iface.dhcpv4_local,
	};
	memcpy(reply.chaddr, req->chaddr, sizeof(reply.chaddr));

	reply.options[0] = 0x63;
	reply.options[1] = 0x82;
	reply.options[2] = 0x53;
	reply.options[3] = 0x63;

	char hostname[256];
	char reqopts[256];
	size_t reqopts_len = 0;
	size_t hostname_len = 0;
	bool accept_fr_nonce = false;

	_dhcpv4_parse_options(data, len, &iface, req, &reqaddr, &reqmsg, &leasetime, hostname, &hostname_len, reqopts, &reqopts_len, &accept_fr_nonce);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz_handle_dhcpv4((void *) data, size);

	return 0;
}
