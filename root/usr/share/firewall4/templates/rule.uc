{%+ if (rule.family && !rule.has_addrs): -%}
	meta nfproto {{ fw4.nfproto(rule.family) }} {%+ endif -%}
{%+ if (!rule.proto.any && !rule.has_ports && !rule.icmp_types && !rule.icmp_codes): -%}
	meta l4proto {{
		(rule.proto.name == 'icmp' && rule.family == 6) ? 'ipv6-icmp' : rule.proto.name
	}} {%+ endif -%}
{%+ if (rule.saddrs_pos): -%}
	{{ fw4.ipproto(rule.family) }} saddr {{ fw4.set(rule.saddrs_pos) }} {%+ endif -%}
{%+ if (rule.saddrs_neg): -%}
	{{ fw4.ipproto(rule.family) }} saddr != {{ fw4.set(rule.saddrs_neg) }} {%+ endif -%}
{%+ if (rule.daddrs_pos): -%}
	{{ fw4.ipproto(rule.family) }} daddr {{ fw4.set(rule.daddrs_pos) }} {%+ endif -%}
{%+ if (rule.daddrs_neg): -%}
	{{ fw4.ipproto(rule.family) }} daddr != {{ fw4.set(rule.daddrs_neg) }} {%+ endif -%}
{%+ if (rule.sports_pos): -%}
	{{ rule.proto.name }} sport {{ fw4.set(rule.sports_pos) }} {%+ endif -%}
{%+ if (rule.sports_neg): -%}
	{{ rule.proto.name }} sport != {{ fw4.set(rule.sports_neg) }} {%+ endif -%}
{%+ if (rule.dports_pos): -%}
	{{ rule.proto.name }} dport {{ fw4.set(rule.dports_pos) }} {%+ endif -%}
{%+ if (rule.dports_neg): -%}
	{{ rule.proto.name }} dport != {{ fw4.set(rule.dports_neg) }} {%+ endif -%}
{%+ if (rule.smacs_pos): -%}
	ether saddr {{ fw4.set(rule.smacs_pos) }} {%+ endif -%}
{%+ if (rule.smacs_neg): -%}
	ether saddr != {{ fw4.set(rule.smacs_neg) }} {%+ endif -%}
{%+ if (rule.icmp_types): -%}
	{{ (rule.family == 4) ? "icmp" : "icmpv6" }} type {{ fw4.set(rule.icmp_types) }} {%+ endif -%}
{%+ if (rule.icmp_codes): -%}
	{{ (rule.family == 4) ? "icmp" : "icmpv6" }} type . {{ (rule.family == 4) ? "icmp" : "icmpv6" }} code {{
		fw4.set(rule.icmp_codes)
	}} {%+ endif -%}
{%+ if (rule.helper): -%}
	ct helper{% if (rule.helper.invert): %} !={% endif %} {{ fw4.quote(rule.helper.name, true) }} {%+ endif -%}
{%+ if (rule.limit): -%}
	limit rate {{ rule.limit.rate }}/{{ rule.limit.unit }}
	{%- if (rule.limit_burst): %} burst {{ rule.limit_burst }} packets{% endif %} {%+ endif -%}
{%+ if (rule.start_date): -%}
	meta time >= {{
		exists(rule.start_date, "hour") ? fw4.datetime(rule.start_date) : fw4.date(rule.start_date)
	}} {%+ endif -%}
{%+ if (rule.stop_date): -%}
	meta time <= {{
		exists(rule.stop_date, "hour") ? fw4.datetime(rule.stop_date) : fw4.date(rule.stop_date)
	}} {%+ endif -%}
{%+ if (rule.start_time): -%}
	meta hour >= {{ fw4.time(rule.start_time) }} {%+ endif -%}
{%+ if (rule.stop_time): -%}
	meta hour <= {{ fw4.time(rule.stop_time) }} {%+ endif -%}
{%+ if (rule.weekdays): -%}
	meta day{% if (rule.weekdays.invert): %} !={% endif %} {{ fw4.set(rule.weekdays.days) }} {%+ endif -%}
{%+ if (rule.mark && rule.mark.mask < 0xFFFFFFFF): -%}
	meta mark and {{ fw4.hex(rule.mark.mask) }} {{
		rule.mark.invert ? '!=' : '=='
	}} {{ fw4.hex(rule.mark.mark) }} {%+ endif -%}
{%+ if (rule.mark && rule.mark.mask == 0xFFFFFFFF): -%}
	meta mark{% if (rule.mark.invert): %} !={% endif %} {{ fw4.hex(rule.mark.mark) }} {%+ endif -%}
{%+ if (rule.dscp): -%}
	dscp{% if (rule.dscp.invert): %} !={% endif %} {{ fw4.hex(rule.dscp.dscp) }} {%+ endif -%}
{%+ if (rule.ipset): -%}
	{{ fw4.concat(rule.ipset.fields) }}{{
		rule.ipset.invert ? ' !=' : ''
	}} @{{ rule.ipset.name }} {%+ endif -%}
{%+ if (rule.counter): -%}
	counter {%+ endif -%}
{%+ if (rule.log): -%}
	log prefix {{ fw4.quote(rule.log, true) }} {%+ endif -%}
{% if (rule.target == "mark"): -%}
	meta mark set {{
		(rule.set_xmark.mask == 0xFFFFFFFF)
			? fw4.hex(rule.set_xmark.mark)
			: (rule.set_xmark.mark == 0)
				? 'mark and ' + fw4.hex(~rule.set_xmark.mask & 0xFFFFFFFF)
				: (rule.set_xmark.mark == rule.set_xmark.mask)
					? 'mark or ' + fw4.hex(rule.set_xmark.mark)
					: (rule.set_xmark.mask == 0)
						? 'mark xor ' + fw4.hex(rule.set_xmark.mark)
						: 'mark and ' + fw4.hex(~r.set_xmark.mask & 0xFFFFFFFF) + ' xor ' + fw4.hex(r.set_xmark.mark)
	}}
{%- elif (rule.target == "dscp"): -%}
	{{ fw4.ipproto(rule.family) }} dscp set {{ fw4.hex(rule.set_dscp.dscp) }}
{%- elif (rule.target == "notrack"): -%}
	notrack
{%- elif (rule.target == "helper"): -%}
	ct helper set {{ fw4.quote(rule.set_helper.name, true) }}
{%- elif (rule.jump_chain): -%}
	jump {{ rule.jump_chain }}
{%- else -%}
	{{ rule.target }}
{%- endif %} comment {{ fw4.quote("!fw4: " + rule.name, true) }}
