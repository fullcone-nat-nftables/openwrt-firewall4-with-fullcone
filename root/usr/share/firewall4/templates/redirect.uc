{%+ if (redirect.family && !redirect.has_addrs): -%}
	meta nfproto {{ fw4.nfproto(redirect.family) }} {%+ endif -%}
{%+ if (!redirect.proto.any && !redirect.has_ports): -%}
	meta l4proto {{
		(redirect.proto.name == 'icmp' && redirect.family == 6) ? 'ipv6-icmp' : redirect.proto.name
	}} {%+ endif -%}
{%+ if (redirect.device): -%}
	oifname {{ fw4.quote(redirect.device, true) }} {%+ endif -%}
{%+ if (redirect.saddrs_pos): -%}
	{{ fw4.ipproto(redirect.family) }} saddr {{ fw4.set(redirect.saddrs_pos) }} {%+ endif -%}
{%+ if (redirect.saddrs_neg): -%}
	{{ fw4.ipproto(redirect.family) }} saddr != {{ fw4.set(redirect.saddrs_neg) }} {%+ endif -%}
{%+ for (let a in redirect.saddrs_masked): -%}
	{{ fw4.ipproto(redirect.family) }} saddr & {{ a.mask }} {{ a.invert ? '!=' : '==' }} {{ a.addr }} {%+ endfor -%}
{%+ if (redirect.daddrs_pos): -%}
	{{ fw4.ipproto(redirect.family) }} daddr {{ fw4.set(redirect.daddrs_pos) }} {%+ endif -%}
{%+ if (redirect.daddrs_neg): -%}
	{{ fw4.ipproto(redirect.family) }} daddr != {{ fw4.set(redirect.daddrs_neg) }} {%+ endif -%}
{%+ for (let a in redirect.daddrs_masked): -%}
	{{ fw4.ipproto(redirect.family) }} daddr & {{ a.mask }} {{ a.invert ? '!=' : '==' }} {{ a.addr }} {%+ endfor -%}
{%+ if (redirect.sports_pos): -%}
	{{ redirect.proto.name }} sport {{ fw4.set(redirect.sports_pos) }} {%+ endif -%}
{%+ if (redirect.sports_neg): -%}
	{{ redirect.proto.name }} sport != {{ fw4.set(redirect.sports_neg) }} {%+ endif -%}
{%+ if (redirect.dports_pos): -%}
	{{ redirect.proto.name }} dport {{ fw4.set(redirect.dports_pos) }} {%+ endif -%}
{%+ if (redirect.dports_neg): -%}
	{{ redirect.proto.name }} dport != {{ fw4.set(redirect.dports_neg) }} {%+ endif -%}
{%+ if (redirect.smacs_pos): -%}
	ether saddr {{ fw4.set(redirect.smacs_pos) }} {%+ endif -%}
{%+ if (redirect.smacs_neg): -%}
	ether saddr != {{ fw4.set(redirect.smacs_neg) }} {%+ endif -%}
{%+ if (redirect.helper): -%}
	ct helper{% if (redirect.helper.invert): %} !={% endif %} {{ fw4.quote(redirect.helper.name, true) }} {%+ endif -%}
{%+ if (redirect.limit): -%}
	limit rate {{ redirect.limit.rate }}/{{ redirect.limit.unit }}
	{%- if (redirect.limit_burst): %} burst {{ redirect.limit_burst }} packets{% endif %} {%+ endif -%}
{%+ if (redirect.start_date && redirect.stop_date): -%}
	meta time {{ fw4.datestamp(redirect.start_date) }}-{{ fw4.datestamp(redirect.stop_date) }} {%+
   elif (redirect.start_date): -%}
	meta time >= {{ fw4.datestamp(redirect.start_date) }} {%+
   elif (redirect.stop_date): -%}
	meta time <= {{ fw4.datestamp(redirect.stop_date) }} {%+
   endif -%}
{%+ if (redirect.start_time && redirect.stop_time): -%}
	meta hour {{ fw4.time(redirect.start_time) }}-{{ fw4.time(redirect.stop_time) }} {%+
   elif (redirect.start_time): -%}
	meta hour >= {{ fw4.time(redirect.start_time) }} {%+
   elif (redirect.stop_time): -%}
	meta hour <= {{ fw4.time(redirect.stop_time) }} {%+
   endif -%}
{%+ if (redirect.weekdays): -%}
	meta day{% if (redirect.weekdays.invert): %} !={% endif %} {{ fw4.set(redirect.weekdays.days) }} {%+ endif -%}
{%+ if (redirect.mark && redirect.mark.mask < 0xFFFFFFFF): -%}
	meta mark and {{ fw4.hex(redirect.mark.mask) }} {{
		redirect.mark.invert ? '!=' : '=='
	}} {{ fw4.hex(redirect.mark.mark) }} {%+ endif -%}
{%+ if (redirect.mark && redirect.mark.mask == 0xFFFFFFFF): -%}
	meta mark{% if (redirect.mark.invert): %} !={% endif %} {{ fw4.hex(redirect.mark.mark) }} {%+ endif -%}
{%+ if (redirect.ipset): -%}
	{{ fw4.concat(redirect.ipset.fields) }}{{
		redirect.ipset.invert ? ' !=' : ''
	}} @{{ redirect.ipset.name }} {%+ endif -%}
{%+ if (redirect.counter): -%}
	counter {%+ endif -%}
{%+ if (redirect.log): -%}
	log prefix {{ fw4.quote(redirect.log, true) }} {%+ endif -%}
{% if (redirect.target == "redirect"): -%}
	redirect{% if (redirect.rport): %} to {{ fw4.port(redirect.rport) }}{% endif %}
{%- elif (redirect.target == "accept" || redirect.target == "masquerade"): -%}
	{{ redirect.target }}
{%- else -%}
	{{ redirect.target }} {{ redirect.raddr ? fw4.host(redirect.raddr, redirect.rport != null) : '' }}
	{%- if (redirect.rport): %}:{{ fw4.port(redirect.rport) }}{% endif %}
{% endif %} comment {{ fw4.quote(`!fw4: ${redirect.name}`, true) }}
