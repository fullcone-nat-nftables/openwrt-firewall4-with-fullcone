{%+ if (rule.family): -%}
	meta nfproto {{ fw4.nfproto(rule.family) }} {%+ endif -%}
{%+ include("zone-match.uc", { egress, rule }) -%}
tcp flags syn tcp option maxseg size set rt mtu {%+ if (zone.log & 2): -%}
	log prefix "MSSFIX {{ zone.name }} out: " {%+ endif -%}
comment "!fw4: Zone {{ zone.name }} {{
	fw4.nfproto(rule.family, true)
}} {{ egress ? "egress" : "ingress" }} MTU fixing"
