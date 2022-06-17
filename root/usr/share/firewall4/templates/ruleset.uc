{%
	let flowtable_devices = fw4.resolve_offload_devices();
	let available_helpers = filter(fw4.helpers(), h => h.available);
	let defined_ipsets = fw4.ipsets();
-%}

table inet fw4
flush table inet fw4
{% if (fw4.check_flowtable()): %}
delete flowtable inet fw4 ft
{% endif %}
{% fw4.includes('ruleset-prepend') %}

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
{% if (length(available_helpers)): %}
	#
	# CT helper definitions
	#

{%  for (let helper in available_helpers): %}
{%   for (let proto in helper.proto): %}
	ct helper {{ helper.name }} {
		type {{ fw4.quote(helper.name, true) }} protocol {{ proto.name }};
	}

{%   endfor %}
{%  endfor %}

{% endif %}
{% if (length(defined_ipsets)): %}
	#
	# Set definitions
	#

{%  for (let set in defined_ipsets): %}
	set {{ set.name }} {
		type {{ fw4.concat(set.types) }}
{%   if (set.maxelem > 0): %}
		size {{ set.maxelem }}
{%   endif %}
{%   if (set.timeout > 0): %}
		timeout {{ set.timeout }}s
{%   endif %}
{%   if (set.interval): %}
		auto-merge
{%   endif %}
{%   if (set.flags): %}
		flags {{ join(',', set.flags) }}
{%   endif %}
{%   fw4.print_setentries(set) %}
	}

{%  endfor %}

{% endif %}
	#
	# Defines
	#

{% for (let zone in fw4.zones()): %}
	define {{ zone.name }}_devices = {{ fw4.set(zone.match_devices, true) }}
	define {{ zone.name }}_subnets = {{ fw4.set(zone.match_subnets, true) }}

{% endfor %}

	#
	# User includes
	#

	include "/etc/nftables.d/*.nft"
{% fw4.includes('table-prepend') %}


	#
	# Filter rules
	#

	chain input {
		type filter hook input priority filter; policy {{ fw4.input_policy(true) }};

		iifname "lo" accept comment "!fw4: Accept traffic from loopback"

{% fw4.includes('chain-prepend', 'input') %}
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
{% fw4.includes('chain-append', 'input') %}
	}

	chain forward {
		type filter hook forward priority filter; policy {{ fw4.forward_policy(true) }};

{% if (length(flowtable_devices) > 0): %}
		meta l4proto { tcp, udp } flow offload @ft;
{% endif %}
{% fw4.includes('chain-prepend', 'forward') %}
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
{% fw4.includes('chain-append', 'forward') %}
{% if (fw4.forward_policy() == "reject"): %}
		jump handle_reject
{% endif %}
	}

	chain output {
		type filter hook output priority filter; policy {{ fw4.output_policy(true) }};

		oifname "lo" accept comment "!fw4: Accept traffic towards loopback"

{% fw4.includes('chain-prepend', 'output') %}
		ct state established,related accept comment "!fw4: Allow outbound established and related flows"
{% if (fw4.default_option("drop_invalid")): %}
		ct state invalid drop comment "!fw4: Drop flows with invalid conntrack state"
{% endif %}
{% for (let rule in fw4.rules("output")): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{% endfor %}
{% for (let zone in fw4.zones()): %}
{%  for (let rule in zone.match_rules): %}
{%   if (zone.dflags.helper): %}
{%    let devices_pos = fw4.filter_loopback_devs(rule.devices_pos, true); %}
{%    let subnets_pos = fw4.filter_loopback_addrs(rule.subnets_pos, true); %}
{%    if (devices_pos || subnets_pos): %}
		{%+ include("zone-jump.uc", { fw4, zone, rule: { ...rule, devices_pos, subnets_pos }, direction: "helper" }) %}
{%    endif %}
{%   endif %}
		{%+ include("zone-jump.uc", { fw4, zone, rule, direction: "output" }) %}
{%  endfor %}
{% endfor %}
{% fw4.includes('chain-append', 'output') %}
{% if (fw4.output_policy() == "reject"): %}
		jump handle_reject
{% endif %}
	}

	chain prerouting {
		type filter hook prerouting priority filter; policy accept;
{% for (let zone in fw4.zones()): %}
{%  if (zone.dflags.helper): %}
{%   for (let rule in zone.match_rules): %}
{%    let devices_pos = fw4.filter_loopback_devs(rule.devices_pos, false); %}
{%    let subnets_pos = fw4.filter_loopback_addrs(rule.subnets_pos, false); %}
{%    if (rule.devices_neg || rule.subnets_neg || devices_pos || subnets_pos): %}
		{%+ include("zone-jump.uc", { fw4, zone, rule: { ...rule, devices_pos, subnets_pos }, direction: "helper" }) %}
{%    endif %}
{%   endfor %}
{%  endif %}
{% endfor %}
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
{%  fw4.includes('chain-prepend', `input_${zone.name}`) %}
{%  for (let rule in fw4.rules(`input_${zone.name}`)): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{%  endfor %}
{%  if (zone.dflags.dnat): %}
		ct status dnat accept comment "!fw4: Accept port redirections"
{%  endif %}
{%  fw4.includes('chain-append', `input_${zone.name}`) %}
		jump {{ zone.input }}_from_{{ zone.name }}
	}

	chain output_{{ zone.name }} {
{%  fw4.includes('chain-prepend', `output_${zone.name}`) %}
{%  for (let rule in fw4.rules(`output_${zone.name}`)): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{%  endfor %}
{%  fw4.includes('chain-append', `output_${zone.name}`) %}
		jump {{ zone.output }}_to_{{ zone.name }}
	}

	chain forward_{{ zone.name }} {
{%  fw4.includes('chain-prepend', `forward_${zone.name}`) %}
{%  for (let rule in fw4.rules(`forward_${zone.name}`)): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{%  endfor %}
{%  if (zone.dflags.dnat): %}
		ct status dnat accept comment "!fw4: Accept port forwards"
{%  endif %}
{%  fw4.includes('chain-append', `forward_${zone.name}`) %}
		jump {{ zone.forward }}_to_{{ zone.name }}
	}

{%  if (zone.dflags.helper): %}
	chain helper_{{ zone.name }} {
{%   for (let rule in fw4.rules(`helper_${zone.name}`)): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{%   endfor %}
	}

{%  endif %}
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
{% fw4.includes('chain-prepend', 'dstnat') %}
{% for (let zone in fw4.zones()): %}
{%  if (zone.dflags.dnat): %}
{%   for (let rule in zone.match_rules): %}
		{%+ include("zone-jump.uc", { fw4, zone, rule, direction: "dstnat" }) %}
{%   endfor %}
{%  endif %}
{% endfor %}
{% fw4.includes('chain-append', 'dstnat') %}
	}

	chain srcnat {
		type nat hook postrouting priority srcnat; policy accept;
{% fw4.includes('chain-prepend', 'srcnat') %}
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
{% fw4.includes('chain-append', 'srcnat') %}
	}

{% for (let zone in fw4.zones()): %}
{%  if (zone.dflags.dnat): %}
	chain dstnat_{{ zone.name }} {
{%   fw4.includes('chain-prepend', `dstnat_${zone.name}`) %}
{%   for (let redirect in fw4.redirects(`dstnat_${zone.name}`)): %}
		{%+ include("redirect.uc", { fw4, redirect }) %}
{%   endfor %}
{%   fw4.includes('chain-append', `dstnat_${zone.name}`) %}
	}

{%  endif %}
{%  if (zone.dflags.snat): %}
	chain srcnat_{{ zone.name }} {
{%   fw4.includes('chain-prepend', `srcnat_${zone.name}`) %}
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
{%   fw4.includes('chain-append', `srcnat_${zone.name}`) %}
	}

{%  endif %}
{% endfor %}

	#
	# Raw rules (notrack)
	#

	chain raw_prerouting {
		type filter hook prerouting priority raw; policy accept;
{% for (let zone in fw4.zones()): %}
{%  if (zone.dflags["notrack"]): %}
{%   for (let rule in zone.match_rules): %}
{%    let devices_pos = fw4.filter_loopback_devs(rule.devices_pos, false); %}
{%    let subnets_pos = fw4.filter_loopback_addrs(rule.subnets_pos, false); %}
{%    if (rule.devices_neg || rule.subnets_neg || devices_pos || subnets_pos): %}
		{%+ include("zone-jump.uc", { fw4, zone, rule: { ...rule, devices_pos, subnets_pos }, direction: "notrack" }) %}
{%    endif %}
{%   endfor %}
{%  endif %}
{% endfor %}
{% fw4.includes('chain-append', 'raw_prerouting') %}
	}

	chain raw_output {
		type filter hook output priority raw; policy accept;
{% fw4.includes('chain-prepend', 'raw_output') %}
{% for (let zone in fw4.zones()): %}
{%  if (zone.dflags["notrack"]): %}
{%   for (let rule in zone.match_rules): %}
{%    let devices_pos = fw4.filter_loopback_devs(rule.devices_pos, true); %}
{%    let subnets_pos = fw4.filter_loopback_addrs(rule.subnets_pos, true); %}
{%    if (devices_pos || subnets_pos): %}
		{%+ include("zone-jump.uc", { fw4, zone, rule: { ...rule, devices_pos, subnets_pos }, direction: "notrack" }) %}
{%    endif %}
{%   endfor %}
{%  endif %}
{% endfor %}
{% fw4.includes('chain-append', 'raw_output') %}
	}

{% for (let zone in fw4.zones()): %}
{%   if (zone.dflags.notrack): %}
	chain notrack_{{ zone.name }} {
{% for (let rule in fw4.rules(`notrack_${zone.name}`)): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{% endfor %}
	}

{%   endif %}
{% endfor %}

	#
	# Mangle rules
	#

	chain mangle_prerouting {
		type filter hook prerouting priority mangle; policy accept;
{% fw4.includes('chain-prepend', 'mangle_prerouting') %}
{% for (let rule in fw4.rules("mangle_prerouting")): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{% endfor %}
{% fw4.includes('chain-append', 'mangle_prerouting') %}
	}

	chain mangle_postrouting {
		type filter hook postrouting priority mangle; policy accept;
{% fw4.includes('chain-prepend', 'mangle_postrouting') %}
{% for (let rule in fw4.rules("mangle_postrouting")): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{% endfor %}
{% fw4.includes('chain-append', 'mangle_postrouting') %}
	}

	chain mangle_input {
		type filter hook input priority mangle; policy accept;
{% fw4.includes('chain-prepend', 'mangle_input') %}
{% for (let rule in fw4.rules("mangle_input")): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{% endfor %}
{% fw4.includes('chain-append', 'mangle_input') %}
	}

	chain mangle_output {
		type route hook output priority mangle; policy accept;
{% fw4.includes('chain-prepend', 'mangle_output') %}
{% for (let rule in fw4.rules("mangle_output")): %}
		{%+ include("rule.uc", { fw4, rule }) %}
{% endfor %}
{% fw4.includes('chain-append', 'mangle_output') %}
	}

	chain mangle_forward {
		type filter hook forward priority mangle; policy accept;
{% fw4.includes('chain-prepend', 'mangle_forward') %}
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
{% fw4.includes('chain-append', 'mangle_forward') %}
	}
{% fw4.includes('table-append') %}
}
{% fw4.includes('ruleset-append') %}
