{%+ if (rule.family): -%}
	meta nfproto {{ fw4.nfproto(rule.family) }} {%+ endif -%}
{%+ if (rule.devices_pos): -%}
	{{ egress ? "oifname" : "iifname" }} {{ fw4.set(rule.devices_pos) }} {%+ endif -%}
{%+ if (rule.devices_neg): -%}
	{{ egress ? "oifname" : "iifname"
	}} != {{ fw4.set(rule.devices_neg) }} {%+ endif -%}
{%+ if (rule.subnets_pos): -%}
	{{ fw4.ipproto(rule.family) }} {{ egress ? "daddr" : "saddr" }} {{ fw4.set(rule.subnets_pos) }} {%+ endif -%}
{%+ if (rule.subnets_neg): -%}
	{{ fw4.ipproto(rule.family) }} {{ egress ? "daddr" : "saddr" }} != {{ fw4.set(rule.subnets_neg) }} {%+ endif -%}
{%+ if (zone.counter): -%}
	counter {%+ endif -%}
{%+ if (verdict != "accept" && (zone.log & 1)): -%}
	log prefix "{{ verdict }} {{ zone.name }} {{ egress ? "out" : "in" }}: " {%+ endif -%}
{% if (verdict == "reject"): -%}
	jump handle_reject comment "!fw4: reject {{ zone.name }} {{ fw4.nfproto(rule.family, true) }} traffic"
{% else -%}
	{{ verdict }} comment "!fw4: {{ verdict }} {{ zone.name }} {{ fw4.nfproto(rule.family, true) }} traffic"
{% endif -%}
