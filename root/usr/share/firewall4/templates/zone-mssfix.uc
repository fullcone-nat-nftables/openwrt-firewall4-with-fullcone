{%+ if (rule.family): -%}
	meta nfproto {{ fw4.nfproto(rule.family) }} {%+ endif -%}
{%+ if (rule.devices_pos): -%}
	{{ egress ? "oifname" : "iifname" }} {{ fw4.set(rule.devices_pos) }} {%+ endif -%}
{%+ if (rule.devices_neg): -%}
	{{ egress ? "oifname" : "iifname" }} != {{ fw4.set(rule.devices_neg) }} {%+ endif -%}
{%+ if (rule.subnets_pos): -%}
	{{ fw4.ipproto(rule.family) }} {{ egress ? "daddr" : "saddr" }} {{ fw4.set(rule.subnets_pos) }} {%+ endif -%}
{%+ if (rule.subnets_neg): -%}
	{{ fw4.ipproto(rule.family) }} {{ egress ? "daddr" : "saddr" }} != {{ fw4.set(rule.subnets_neg) }} {%+ endif -%}
tcp flags syn tcp option maxseg size set rt mtu {%+ if (zone.log & 2): -%}
	log prefix "MSSFIX {{ zone.name }} out: " {%+ endif -%}
comment "!fw4: Zone {{ zone.name }} {{
	fw4.nfproto(rule.family, true)
}} {{ egress ? "egress" : "ingress" }} MTU fixing"
