{% let flowtable_devices = fw4.resolve_offload_devices(); -%}

table inet fw4
flush table inet fw4
{% if (fw4.check_flowtable()): %}
delete flowtable inet fw4 ft
{% endif %}

table inet fw4 {
{% if (length(flowtable_devices) > 0): %}
	#
	# Flowtable
	#

	flowtable ft {
		hook ingress priority 0;
		devices = {{ fw4.set(flowtable_devices, true) }};
{% if (fw4.default_option("flow_offloading_hw")): %}
		flags offload;
{% endif %}
	}

{% endif %}
	#
	# Set definitions
	#

{% for (let set in fw4.ipsets()): %}
	set {{ set.name }} {
		type {{ fw4.concat(set.types) }}
{%  if (set.maxelem > 0): %}
		size {{ set.maxelem }}
{%  endif %}
{%  if (set.timeout >= 0): %}
		timeout {{ set.timeout }}s
{% endif %}
{%  if (set.interval): %}
		flags interval
		auto-merge
{%  endif %}
{%  fw4.print_setentries(set) %}
	}

{% endfor %}

	#
	# Defines
	#

{% for (let zone in fw4.zones()): %}
{%  if (length(zone.match_devices)): %}
	define {{ zone.name }}_devices = {{ fw4.set(zone.match_devices, true) }}
{%  endif %}
{%  if (length(zone.match_subnets)): %}
	define {{ zone.name }}_subnets = {{ fw4.set(zone.match_subnets, true) }}
{%  endif %}
{% endfor %}

	#
	# User includes
	#

	include "/etc/nftables.d/*.nft"


	#
	# Filter rules
	#

	chain input {
		type filter hook input priority filter; policy {{ fw4.input_policy(true) }};

		iifname "lo" accept comment "!fw4: Accept traffic from loopback"

		ct state established,related accept comment "!fw4: Allow inbound established and related flows"
{% if (fw4.default_option("drop_invalid")): %}
		ct state invalid drop comment "!fw4: Drop flows with invalid conntrack state"
{% endif %}
{% if (fw4.default_option("synflood_protect") && fw4.default_option("synflood_rate")): %}
		tcp flags & (fin | syn | rst | ack) == syn jump syn_flood comment "!fw4: Rate limit TCP syn packets"
{% endif %}
{% for (let rule in fw4.rules("input")): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{% endfor %}
{% for (let zone in fw4.zones()): for (let rule in zone.match_rules): %}
		{%+ include("zone-jump.uc", { fw4, zone, rule, direction: "input" }) %}
{% endfor; endfor %}
{% if (fw4.input_policy() == "reject"): %}
		jump handle_reject
{% endif %}
	}

	chain forward {
		type filter hook forward priority filter; policy {{ fw4.forward_policy(true) }};

{% if (length(flowtable_devices) > 0): %}
		meta l4proto { tcp, udp } flow offload @ft;
{% endif %}
		ct state established,related accept comment "!fw4: Allow forwarded established and related flows"
{% if (fw4.default_option("drop_invalid")): %}
		ct state invalid drop comment "!fw4: Drop flows with invalid conntrack state"
{% endif %}
{% for (let rule in fw4.rules("forward")): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{% endfor %}
{% for (let zone in fw4.zones()): for (let rule in zone.match_rules): %}
		{%+ include("zone-jump.uc", { fw4, zone, rule, direction: "forward" }) %}
{% endfor; endfor %}
{% if (fw4.forward_policy() == "reject"): %}
		jump handle_reject
{% endif %}
	}

	chain output {
		type filter hook output priority filter; policy {{ fw4.output_policy(true) }};

		oifname "lo" accept comment "!fw4: Accept traffic towards loopback"

		ct state established,related accept comment "!fw4: Allow outbound established and related flows"
{% if (fw4.default_option("drop_invalid")): %}
		ct state invalid drop comment "!fw4: Drop flows with invalid conntrack state"
{% endif %}
{% for (let rule in fw4.rules("output")): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{% endfor %}
{% for (let zone in fw4.zones()): for (let rule in zone.match_rules): %}
		{%+ include("zone-jump.uc", { fw4, zone, rule, direction: "output" }) %}
{% endfor; endfor %}
{% if (fw4.output_policy() == "reject"): %}
		jump handle_reject
{% endif %}
	}

	chain handle_reject {
		meta l4proto tcp reject with {{
			(fw4.default_option("tcp_reject_code") != "tcp-reset")
				? `icmpx type ${fw4.default_option("tcp_reject_code")}`
				: "tcp reset"
		}} comment "!fw4: Reject TCP traffic"
		reject with {{
			(fw4.default_option("any_reject_code") != "tcp-reset")
				? `icmpx type ${fw4.default_option("any_reject_code")}`
				: "tcp reset"
		}} comment "!fw4: Reject any other traffic"
	}

{% if (fw4.default_option("synflood_protect") && fw4.default_option("synflood_rate")):
	let r = fw4.default_option("synflood_rate");
	let b = fw4.default_option("synflood_burst");
%}
	chain syn_flood {
		limit rate {{ r.rate }}/{{ r.unit }}
		{%- if (b): %} burst {{ b }} packets{% endif %} return comment "!fw4: Accept SYN packets below rate-limit"
		drop comment "!fw4: Drop excess packets"
	}

{% endif %}
{% for (let zone in fw4.zones()): %}
	chain input_{{ zone.name }} {
{%  for (let rule in fw4.rules(`input_${zone.name}`)): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{%  endfor %}
{%  if (zone.dflags.dnat): %}
		ct status dnat accept comment "!fw4: Accept port redirections"
{%  endif %}
		jump {{ zone.input }}_from_{{ zone.name }}
	}

	chain output_{{ zone.name }} {
{%  for (let rule in fw4.rules(`output_${zone.name}`)): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{%  endfor %}
		jump {{ zone.output }}_to_{{ zone.name }}
	}

	chain forward_{{ zone.name }} {
{%  for (let rule in fw4.rules(`forward_${zone.name}`)): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{%  endfor %}
{%  if (zone.dflags.dnat): %}
		ct status dnat accept comment "!fw4: Accept port forwards"
{%  endif %}
		jump {{ zone.forward }}_to_{{ zone.name }}
	}

{%  for (let verdict in ["accept", "reject", "drop"]): %}
{%   if (zone.sflags[verdict]): %}
	chain {{ verdict }}_from_{{ zone.name }} {
{%    for (let rule in zone.match_rules): %}
		{%+ include("zone-verdict.uc", { fw4, zone, rule, egress: false, verdict }) %}
{%    endfor %}
	}

{%   endif %}
{%   if (zone.dflags[verdict]): %}
	chain {{ verdict }}_to_{{ zone.name }} {
{%   for (let rule in zone.match_rules): %}
		{%+ include("zone-verdict.uc", { fw4, zone, rule, egress: true, verdict }) %}
{%   endfor %}
	}

{%   endif %}
{%  endfor %}
{% endfor %}

	#
	# NAT rules
	#

	chain dstnat {
		type nat hook prerouting priority dstnat; policy accept;
{% for (let zone in fw4.zones()): %}
{%  if (zone.dflags.dnat): %}
{%   for (let rule in zone.match_rules): %}
		{%+ include("zone-jump.uc", { fw4, zone, rule, direction: "dstnat" }) %}
{%   endfor %}
{%  endif %}
{% endfor %}
	}

	chain srcnat {
		type nat hook postrouting priority srcnat; policy accept;
{% for (let redirect in fw4.redirects("srcnat")): %}
		{%+ include("redirect.uc", { fw4, redirect }) %}
{% endfor %}
{% for (let zone in fw4.zones()): %}
{%  if (zone.dflags.snat): %}
{%   for (let rule in zone.match_rules): %}
		{%+ include("zone-jump.uc", { fw4, zone, rule, direction: "srcnat" }) %}
{%   endfor %}
{%  endif %}
{% endfor %}
	}

{% for (let zone in fw4.zones()): %}
{%  if (zone.dflags.dnat): %}
	chain dstnat_{{ zone.name }} {
{%   for (let redirect in fw4.redirects(`dstnat_${zone.name}`)): %}
		{%+ include("redirect.uc", { fw4, redirect }) %}
{%   endfor %}
	}

{%  endif %}
{%  if (zone.dflags.snat): %}
	chain srcnat_{{ zone.name }} {
{%   for (let redirect in fw4.redirects(`srcnat_${zone.name}`)): %}
		{%+ include("redirect.uc", { fw4, redirect }) %}
{%   endfor %}
{%   if (zone.masq): %}
{%    for (let saddrs in zone.masq4_src_subnets): %}
{%     for (let daddrs in zone.masq4_dest_subnets): %}
		{%+ include("zone-masq.uc", { fw4, zone, family: 4, saddrs, daddrs }) %}
{%     endfor %}
{%    endfor %}
{%   endif %}
{%   if (zone.masq6): %}
{%    for (let saddrs in zone.masq6_src_subnets): %}
{%     for (let daddrs in zone.masq6_dest_subnets): %}
		{%+ include("zone-masq.uc", { fw4, zone, family: 6, saddrs, daddrs }) %}
{%     endfor %}
{%    endfor %}
{%   endif %}
	}

{%  endif %}
{% endfor %}

	#
	# Raw rules (notrack & helper)
	#

	chain raw_prerouting {
		type filter hook prerouting priority raw; policy accept;
{% for (let target in ["helper", "notrack"]): %}
{%  for (let zone in fw4.zones()): %}
{%   if (zone.dflags[target]): %}
{%    for (let rule in zone.match_rules): %}
{%     let devices_pos = fw4.filter_loopback_devs(rule.devices_pos, false); %}
{%     let subnets_pos = fw4.filter_loopback_addrs(rule.subnets_pos, false); %}
{%     if (rule.devices_neg || rule.subnets_neg || devices_pos || subnets_pos): %}
		{%+ if (rule.family): -%}
			meta nfproto {{ fw4.nfproto(rule.family) }} {%+ endif -%}
		{%+ include("zone-match.uc", { fw4, egress: false, rule: { ...rule, devices_pos, subnets_pos } }) -%}
		jump {{ target }}_{{ zone.name }} comment "!fw4: {{ zone.name }} {{ fw4.nfproto(rule.family, true) }} {{
			(target == "helper") ? "CT helper assignment" : "CT bypass"
		}}"
{%     endif %}
{%    endfor %}
{%   endif %}
{%  endfor %}
{% endfor %}
	}

	chain raw_output {
		type filter hook output priority raw; policy accept;
{% for (let target in ["helper", "notrack"]): %}
{%  for (let zone in fw4.zones()): %}
{%   if (zone.dflags[target]): %}
{%    for (let rule in zone.match_rules): %}
{%     let devices_pos = fw4.filter_loopback_devs(rule.devices_pos, true); %}
{%     let subnets_pos = fw4.filter_loopback_addrs(rule.subnets_pos, true); %}
{%     if (devices_pos || subnets_pos): %}
		{%+ if (rule.family): -%}
			meta nfproto {{ fw4.nfproto(rule.family) }} {%+ endif -%}
		{%+ include("zone-match.uc", { fw4, egress: false, rule: { ...rule, devices_pos, subnets_pos } }) -%}
		jump {{ target }}_{{ zone.name }} comment "!fw4: {{ zone.name }} {{ fw4.nfproto(rule.family, true) }} {{
			(target == "helper") ? "CT helper assignment" : "CT bypass"
		}}"
{%     endif %}
{%    endfor %}
{%   endif %}
{%  endfor %}
{% endfor %}
	}

{% for (let helper in fw4.helpers()): %}
{%  if (helper.available): %}
{%   for (let proto in helper.proto): %}
	ct helper {{ helper.name }} {
		type {{ fw4.quote(helper.name, true) }} protocol {{ proto.name }};
	}

{%   endfor %}
{%  endif %}
{% endfor %}
{% for (let target in ["helper", "notrack"]): %}
{%  for (let zone in fw4.zones()): %}
{%   if (zone.dflags[target]): %}
	chain {{ target }}_{{ zone.name }} {
{% for (let rule in fw4.rules(`${target}_${zone.name}`)): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{% endfor %}
	}

{%   endif %}
{%  endfor %}
{% endfor %}

	#
	# Mangle rules
	#

	chain mangle_prerouting {
		type filter hook prerouting priority mangle; policy accept;
{% for (let rule in fw4.rules("mangle_prerouting")): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{% endfor %}
	}

	chain mangle_postrouting {
		type filter hook postrouting priority mangle; policy accept;
{% for (let rule in fw4.rules("mangle_postrouting")): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{% endfor %}
	}

	chain mangle_input {
		type filter hook input priority mangle; policy accept;
{% for (let rule in fw4.rules("mangle_input")): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{% endfor %}
	}

	chain mangle_output {
		type filter hook output priority mangle; policy accept;
{% for (let rule in fw4.rules("mangle_output")): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{% endfor %}
	}

	chain mangle_forward {
		type filter hook forward priority mangle; policy accept;
{% for (let rule in fw4.rules("mangle_forward")): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{% endfor %}
{% for (let zone in fw4.zones()): %}
{%  if (zone.mtu_fix): %}
{%   for (let rule in zone.match_rules): %}
		{%+ include("zone-mssfix.uc", { fw4, zone, rule, egress: false }) %}
		{%+ include("zone-mssfix.uc", { fw4, zone, rule, egress: true }) %}
{%   endfor %}
{%  endif %}
{% endfor %}
	}
}
