meta nfproto {{ fw4.nfproto(family) }} {%+ if (saddrs && saddrs[0]): -%}
	{{ fw4.ipproto(family) }} saddr {{ fw4.set(map(saddrs[0], fw4.cidr)) }} {%+ endif -%}
{%+ if (saddrs && saddrs[1]): -%}
	{{ fw4.ipproto(family) }} saddr != {{ fw4.set(map(saddrs[1], fw4.cidr)) }} {%+ endif -%}
{%+ for (let a in (saddrs ? saddrs[2] : [])): -%}
	{{ fw4.ipproto(family) }} saddr & {{ a.mask }} {{ a.invert ? '!=' : '==' }} {{ a.addr }} {%+ endfor -%}
{%+ if (daddrs && daddrs[0]): -%}
	{{ fw4.ipproto(family) }} daddr {{ fw4.set(map(daddrs[0], fw4.cidr)) }} {%+ endif -%}
{%+ if (daddrs && daddrs[1]): -%}
	{{ fw4.ipproto(family) }} daddr != {{ fw4.set(map(daddrs[1], fw4.cidr)) }} {%+ endif -%}
{%+ for (let a in (daddrs ? daddrs[2] : [])): -%}
	{{ fw4.ipproto(family) }} daddr & {{ a.mask }} {{ a.invert ? '!=' : '==' }} {{ a.addr }} {%+ endfor -%}
masquerade comment "!fw4: Masquerade {{ fw4.nfproto(family, true) }} {{ zone.name }} traffic"
