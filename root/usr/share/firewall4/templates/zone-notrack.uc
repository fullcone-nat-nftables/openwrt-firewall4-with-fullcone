{%+
	let devs = fw4.filter_loopback_devs(fw4.devices_pos, output),
	    nets = fw4.filter_loopback_addrs(fw4.subnets_pos, output);

	if (!((output && (length(devs) || length(nets))) ||
	      (!output && (rule.devices_neg || rule.subnets_neg || length(devs) || length(nets)))))
	    return;
-%}
{%+ if (rule.family): -%}
	meta nfproto {{ fw4.nfproto(rule.family) }} {%+ endif -%}
{%+ if (length(devs)): -%}
	iifname {{ fw4.set(devs) }} {%+ endif -%}
{%+ if (rule.devices_neg): -%}
	iifname != {{ fw4.set(rule.devices_neg) }} {%+ endif -%}
{%+ if (length(nets)): -%}
	{{ fw4.ipproto(rule.family) }} saddr {{ fw4.set(nets) }} {%+ endif -%}
{%+ if (rule.subnets_neg): -%}
	{{ fw4.ipproto(rule.family) }} saddr != {{ fw4.set(rule.subnets_neg) }} {%+ endif -%}
jump notrack_{{ zone.name }} comment "!fw4: {{ zone.name }} {{ fw4.nfproto(rule.family, true) }} CT bypass"
