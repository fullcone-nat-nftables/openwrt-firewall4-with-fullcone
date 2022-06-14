{%+ if (rule.family): -%}
	meta nfproto {{ fw4.nfproto(rule.family) }} {%+ endif -%}
{%+ include("zone-match.uc", { egress: (direction in ["output", "srcnat"]), rule }) -%}
jump {{ direction }}_{{ zone.name }} comment "!fw4: Handle {{ zone.name }} {{
	fw4.nfproto(rule.family, true)
}} {{ direction }} {{ (direction == 'helper') ? "assignment" : "traffic" }}"
