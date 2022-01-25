{%+ if (rule.family): -%}
	meta nfproto {{ fw4.nfproto(rule.family) }} {%+ endif -%}
{%+ include("zone-match.uc", { egress, rule }) -%}
{%+ if (zone.counter): -%}
	counter {%+ endif -%}
{%+ if (verdict != "accept" && (zone.log & 1)): -%}
	log prefix "{{ verdict }} {{ zone.name }} {{ egress ? "out" : "in" }}: " {%+ endif -%}
{% if (verdict == "reject"): -%}
	jump handle_reject comment "!fw4: reject {{ zone.name }} {{ fw4.nfproto(rule.family, true) }} traffic"
{% else -%}
	{{ verdict }} comment "!fw4: {{ verdict }} {{ zone.name }} {{ fw4.nfproto(rule.family, true) }} traffic"
{% endif -%}
