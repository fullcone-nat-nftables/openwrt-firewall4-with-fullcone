{%+ if (rule.devices_pos): -%}
	{{ egress ? "oifname" : "iifname" }} {{ fw4.set(rule.devices_pos) }} {%+ endif -%}
{%+ if (rule.devices_neg): -%}
	{{ egress ? "oifname" : "iifname" }} != {{ fw4.set(rule.devices_neg) }} {%+ endif -%}
{%+ for (let wcndev in rule.devices_neg_wildcard): -%}
	{{ egress ? "oifname" : "iifname" }} != {{ fw4.quote(wcndev) }} {%+ endfor -%}
{%+ if (rule.subnets_pos): -%}
	{{ fw4.ipproto(rule.family) }} {{ egress ? "daddr" : "saddr" }} {{ fw4.set(rule.subnets_pos) }} {%+ endif -%}
{%+ if (rule.subnets_neg): -%}
	{{ fw4.ipproto(rule.family) }} {{ egress ? "daddr" : "saddr" }} != {{ fw4.set(rule.subnets_neg) }} {%+ endif -%}
{%+ for (let subnet in rule.subnets_masked): -%}
	{{ fw4.ipproto(rule.family) }} {{ egress ? "daddr" : "saddr" }} & {{ subnet.mask }} {{ subnet.invert ? '!=' : '==' }} {{ subnet.addr }} {%+ endfor -%}
