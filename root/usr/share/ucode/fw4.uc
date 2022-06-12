// /usr/share/ucode/fw4.uc

const fs = require("fs");
const uci = require("uci");
const ubus = require("ubus");

const STATEFILE = "/var/run/fw4.state";

const PARSE_LIST   = 0x01;
const FLATTEN_LIST = 0x02;
const NO_INVERT    = 0x04;
const UNSUPPORTED  = 0x08;
const REQUIRED     = 0x10;
const DEPRECATED   = 0x20;

const ipv4_icmptypes = {
	"any": [ 0xFF, 0, 0xFF ],
	"echo-reply": [ 0, 0, 0xFF ],
	"pong": [ 0, 0, 0xFF ], /* Alias */

	"destination-unreachable": [ 3, 0, 0xFF ],
	"network-unreachable": [ 3, 0, 0 ],
	"host-unreachable": [ 3, 1, 1 ],
	"protocol-unreachable": [ 3, 2, 2 ],
	"port-unreachable": [ 3, 3, 3 ],
	"fragmentation-needed": [ 3, 4, 4 ],
	"source-route-failed": [ 3, 5, 5 ],
	"network-unknown": [ 3, 6, 6 ],
	"host-unknown": [ 3, 7, 7 ],
	"network-prohibited": [ 3, 9, 9 ],
	"host-prohibited": [ 3, 10, 10 ],
	"TOS-network-unreachable": [ 3, 11, 11 ],
	"TOS-host-unreachable": [ 3, 12, 12 ],
	"communication-prohibited": [ 3, 13, 13 ],
	"host-precedence-violation": [ 3, 14, 14 ],
	"precedence-cutoff": [ 3, 15, 15 ],

	"source-quench": [ 4, 0, 0xFF ],

	"redirect": [ 5, 0, 0xFF ],
	"network-redirect": [ 5, 0, 0 ],
	"host-redirect": [ 5, 1, 1 ],
	"TOS-network-redirect": [ 5, 2, 2 ],
	"TOS-host-redirect": [ 5, 3, 3 ],

	"echo-request": [ 8, 0, 0xFF ],
	"ping": [ 8, 0, 0xFF ], /* Alias */

	"router-advertisement": [ 9, 0, 0xFF ],

	"router-solicitation": [ 10, 0, 0xFF ],

	"time-exceeded": [ 11, 0, 0xFF ],
	"ttl-exceeded": [ 11, 0, 0xFF ], /* Alias */
	"ttl-zero-during-transit": [ 11, 0, 0 ],
	"ttl-zero-during-reassembly": [ 11, 1, 1 ],

	"parameter-problem": [ 12, 0, 0xFF ],
	"ip-header-bad": [ 12, 0, 0 ],
	"required-option-missing": [ 12, 1, 1 ],

	"timestamp-request": [ 13, 0, 0xFF ],

	"timestamp-reply": [ 14, 0, 0xFF ],

	"address-mask-request": [ 17, 0, 0xFF ],

	"address-mask-reply": [ 18, 0, 0xFF ]
};

const ipv6_icmptypes = {
	"destination-unreachable": [ 1, 0, 0xFF ],
	"no-route": [ 1, 0, 0 ],
	"communication-prohibited": [ 1, 1, 1 ],
	"address-unreachable": [ 1, 3, 3 ],
	"port-unreachable": [ 1, 4, 4 ],

	"packet-too-big": [ 2, 0, 0xFF ],

	"time-exceeded": [ 3, 0, 0xFF ],
	"ttl-exceeded": [ 3, 0, 0xFF ], /* Alias */
	"ttl-zero-during-transit": [ 3, 0, 0 ],
	"ttl-zero-during-reassembly": [ 3, 1, 1 ],

	"parameter-problem": [ 4, 0, 0xFF ],
	"bad-header": [ 4, 0, 0 ],
	"unknown-header-type": [ 4, 1, 1 ],
	"unknown-option": [ 4, 2, 2 ],

	"echo-request": [ 128, 0, 0xFF ],
	"ping": [ 128, 0, 0xFF ], /* Alias */

	"echo-reply": [ 129, 0, 0xFF ],
	"pong": [ 129, 0, 0xFF ], /* Alias */

	"router-solicitation": [ 133, 0, 0xFF ],

	"router-advertisement": [ 134, 0, 0xFF ],

	"neighbour-solicitation": [ 135, 0, 0xFF ],
	"neighbor-solicitation": [ 135, 0, 0xFF ], /* Alias */

	"neighbour-advertisement": [ 136, 0, 0xFF ],
	"neighbor-advertisement": [ 136, 0, 0xFF ], /* Alias */

	"redirect": [ 137, 0, 0xFF ]
};

const dscp_classes = {
	"CS0": 0x00,
	"CS1": 0x08,
	"CS2": 0x10,
	"CS3": 0x18,
	"CS4": 0x20,
	"CS5": 0x28,
	"CS6": 0x30,
	"CS7": 0x38,
	"BE": 0x00,
	"LE": 0x01,
	"AF11": 0x0a,
	"AF12": 0x0c,
	"AF13": 0x0e,
	"AF21": 0x12,
	"AF22": 0x14,
	"AF23": 0x16,
	"AF31": 0x1a,
	"AF32": 0x1c,
	"AF33": 0x1e,
	"AF41": 0x22,
	"AF42": 0x24,
	"AF43": 0x26,
	"EF": 0x2e
};

function to_mask(bits, v6) {
	let m = [], n = false;

	if (bits < 0) {
		n = true;
		bits = -bits;
	}

	if (bits > (v6 ? 128 : 32))
		return null;

	for (let i = 0; i < (v6 ? 16 : 4); i++) {
		let b = (bits < 8) ? bits : 8;
		m[i] = (n ? ~(0xff << (8 - b)) : (0xff << (8 - b))) & 0xff;
		bits -= b;
	}

	return arrtoip(m);
}

function to_bits(mask) {
	let a = iptoarr(mask);

	if (!a)
		return null;

	let bits = 0;

	for (let i = 0, z = false; i < length(a); i++) {
		z ||= !a[i];

		while (!z && (a[i] & 0x80)) {
			a[i] = (a[i] << 1) & 0xff;
			bits++;
		}

		if (a[i])
			return null;
	}

	return bits;
}

function apply_mask(addr, mask) {
	let a = iptoarr(addr);

	if (!a)
		return null;

	if (type(mask) == "int") {
		for (let i = 0; i < length(a); i++) {
			let b = (mask < 8) ? mask : 8;
			a[i] &= (0xff << (8 - b)) & 0xff;
			mask -= b;
		}
	}
	else {
		let m = iptoarr(mask);

		if (!m || length(a) != length(m))
			return null;

		for (let i = 0; i < length(a); i++)
			a[i] &= m[i];
	}

	return arrtoip(a);
}

function to_array(x) {
	if (type(x) == "array")
		return x;

	if (x == null)
		return [];

	if (type(x) == "object")
		return [ x ];

	x = trim("" + x);

	return (x == "") ? [] : split(x, /[ \t]+/);
}

function filter_pos(x) {
	let rv = filter(x, e => !e.invert);
	return length(rv) ? rv : null;
}

function filter_neg(x) {
	let rv = filter(x, e => e.invert);
	return length(rv) ? rv : null;
}

function null_if_empty(x) {
	return length(x) ? x : null;
}

function subnets_split_af(x) {
	let rv = {};

	for (let ag in to_array(x)) {
		for (let a in filter(ag.addrs, a => (a.family == 4)))
			push(rv[0] ||= [], { ...a, invert: ag.invert });

		for (let a in filter(ag.addrs, a => (a.family == 6)))
			push(rv[1] ||= [], { ...a, invert: ag.invert });
	}

	if (rv[0] || rv[1])
		rv.family = (!rv[0] ^ !rv[1]) ? (rv[0] ? 4 : 6) : 0;

	return rv;
}

function subnets_group_by_masking(x) {
	let groups = [], plain = [], nc = [], invert_plain = [], invert_masked = [];

	for (let a in to_array(x)) {
		if (a.bits == -1 && !a.invert)
			push(nc, a);
		else if (!a.invert)
			push(plain, a);
		else if (a.bits == -1)
			push(invert_masked, a);
		else
			push(invert_plain, a);
	}

	for (let a in nc)
		push(groups, [ null, null_if_empty(invert_plain), [ a, ...invert_masked ] ]);

	if (length(plain)) {
		push(groups, [
			plain,
			null_if_empty(invert_plain),
			null_if_empty(invert_masked)
		]);
	}
	else if (!length(groups)) {
		push(groups, [
			null,
			null_if_empty(invert_plain),
			null_if_empty(invert_masked)
		]);
	}

	return groups;
}

function ensure_tcpudp(x) {
	if (length(filter(x, p => (p.name == "tcp" || p.name == "udp"))))
		return true;

	let rest = filter(x, p => !p.any),
	    any = filter(x, p => p.any);

	if (length(any) && !length(rest)) {
		splice(x, 0);
		push(x, { name: "tcp" }, { name: "udp" });
		return true;
	}

	return false;
}

let is_family = (x, v) => (!x.family || x.family == v);
let family_is_ipv4 = (x) => (!x.family || x.family == 4);
let family_is_ipv6 = (x) => (!x.family || x.family == 6);

function infer_family(f, objects) {
	let res = f;
	let by = null;

	for (let i = 0; i < length(objects); i += 2) {
		let objs = to_array(objects[i]),
		    desc = objects[i + 1];

		for (let obj in objs) {
			if (!obj || !obj.family || obj.family == res)
				continue;

			if (!res) {
				res = obj.family;
				by = obj.desc;
				continue;
			}

			return by
				? `references IPv${obj.family} only ${desc} but is restricted to IPv${res} by ${by}`
				: `is restricted to IPv${res} but referenced ${desc} is IPv${obj.family} only`;
		}
	}

	return res;
}

function map_setmatch(set, match, proto) {
	if (!set || (('inet_service' in set.types) && proto != 'tcp' && proto != 'udp'))
		return null;

	let fields = [];

	for (let i, t in set.types) {
		let dir = ((match.dir?.[i] || set.directions[i] || 'src') == 'src' ? 's' : 'd');

		switch (t) {
		case 'ipv4_addr':
			fields[i] = `ip ${dir}addr`;
			break;

		case 'ipv6_addr':
			fields[i] = `ip6 ${dir}addr`;
			break;

		case 'ether_addr':
			if (dir != 's')
				return NaN;

			fields[i] = 'ether saddr';
			break;

		case 'inet_service':
			fields[i] = `${proto} ${dir}port`;
			break;
		}
	}

	return fields;
}

function resolve_lower_devices(devstatus, devname, require_hwoffload) {
	let dir = fs.opendir(`/sys/class/net/${devname}`);
	let devs = [];

	if (dir) {
		switch (devstatus[devname]?.devtype) {
		case 'vlan':
		case 'bridge':
			let e;

			while ((e = dir.read()) != null)
				if (index(e, "lower_") === 0)
					push(devs, ...resolve_lower_devices(devstatus, substr(e, 6), require_hwoffload));

			break;

		default:
			if (!require_hwoffload || devstatus[devname]?.["hw-tc-offload"])
				push(devs, devname);

			break;
		}

		dir.close();
	}

	return devs;
}

function nft_json_command(...args) {
	let cmd = [ "/usr/sbin/nft", "--terse", "--json", ...args ];
	let nft = fs.popen(join(" ", cmd), "r");
	let info;

	if (nft) {
		try {
			info = filter(json(nft.read("all"))?.nftables,
				item => (type(item) == "object" && !item.metainfo));
		}
		catch (e) {
			warn(`Unable to parse nftables JSON output: ${e}\n`);
		}

		nft.close();
	}
	else {
		warn(`Unable to popen() ${cmd}: ${fs.error()}\n`);
	}

	return info || [];
}

function nft_try_hw_offload(devices) {
	let nft_test = `
		add table inet fw4-hw-offload-test;
		add flowtable inet fw4-hw-offload-test ft {
			hook ingress priority 0;
			devices = { "${join('", "', devices)}" };
			flags offload;
		}
	`;

	let rc = system(`/usr/sbin/nft -c '${replace(nft_test, "'", "'\\''")}' 2>/dev/null`);

	return (rc == 0);
}

function nft_try_fullcone() {
	let nft_test =
		'add table inet fw4-fullcone-test; ' +
		'add chain inet fw4-fullcone-test dstnat { ' +
			'type nat hook prerouting priority -100; policy accept; ' +
			'fullcone; ' +
		'}; ' +
		'add chain inet fw4-fullcone-test srcnat { ' +
			'type nat hook postrouting priority -100; policy accept; ' +
			'fullcone; ' +
		'}; ';
	let cmd = sprintf("/usr/sbin/nft -c '%s' 2>/dev/null", replace(nft_test, "'", "'\\''"));
	let ok = system(cmd) == 0;
	if (!ok) {
		warn("nft_try_fullcone: cmd "+ cmd + "\n");
	}
	return ok;
}


return {
	read_kernel_version: function() {
		let fd = fs.open("/proc/version", "r"),
		    v = 0;

		if (fd) {
		    let m = match(fd.read("line"), /^Linux version ([0-9]+)\.([0-9]+)\.([0-9]+)/);

		    v = m ? (+m[1] << 24) | (+m[2] << 16) | (+m[3] << 8) : 0;
		    fd.close();
		}

		return v;
	},

	resolve_offload_devices: function() {
		if (!this.default_option("flow_offloading"))
			return [];

		let devstatus = null;
		let devices = [];
		let bus = ubus.connect();

		if (bus) {
			devstatus = bus.call("network.device", "status") || {};
			bus.disconnect();
		}

		if (this.default_option("flow_offloading_hw")) {
			for (let zone in this.zones())
				for (let device in zone.related_physdevs)
					push(devices, ...resolve_lower_devices(devstatus, device, true));

			devices = sort(uniq(devices));

			if (length(devices) && nft_try_hw_offload(devices))
				return devices;

			this.warn('Hardware flow offloading unavailable, falling back to software offloading');
			this.state.defaults.flow_offloading_hw = false;

			devices = [];
		}

		for (let zone in this.zones())
			for (let device in zone.related_physdevs)
				push(devices, ...resolve_lower_devices(devstatus, device, false));

		return sort(uniq(devices));
	},

	check_set_types: function() {
		let sets = {};

		for (let item in nft_json_command("list", "sets", "inet"))
			if (item.set?.table == "fw4")
				sets[item.set.name] = (type(item.set.type) == "array") ? item.set.type : [ item.set.type ];

		return sets;
	},

	check_flowtable: function() {
		for (let item in nft_json_command("list", "flowtables", "inet"))
			if (item.flowtable?.table == "fw4" && item.flowtable?.name == "ft")
				return true;

		return false;
	},

	read_state: function() {
		let fd = fs.open(STATEFILE, "r");
		let state = null;

		if (fd) {
			try {
				state = json(fd.read("all"));
			}
			catch (e) {
				warn(`Unable to parse '${STATEFILE}': ${e}\n`);
			}

			fd.close();
		}

		return state;
	},

	read_ubus: function() {
		let self = this,
		    ifaces, services,
		    rules = [], networks = {},
		    bus = ubus.connect();

		if (bus) {
			ifaces = bus.call("network.interface", "dump");
		    services = bus.call("service", "get_data", { "type": "firewall" });

		    bus.disconnect();
		}
		else {
			warn(`Unable to connect to ubus: ${ubus.error()}\n`);
		}


		//
		// Gather logical network information from ubus
		//

		if (type(ifaces?.interface) == "array") {
			for (let ifc in ifaces.interface) {
				let net = {
					up: ifc.up,
					device: ifc.l3_device,
					physdev: ifc.device,
					zone: ifc.data?.zone
				};

				if (type(ifc["ipv4-address"]) == "array") {
					for (let addr in ifc["ipv4-address"]) {
						push(net.ipaddrs ||= [], {
							family: 4,
							addr: addr.address,
							mask: to_mask(addr.mask, false),
							bits: addr.mask
						});
					}
				}

				if (type(ifc["ipv6-address"]) == "array") {
					for (let addr in ifc["ipv6-address"]) {
						push(net.ipaddrs ||= [], {
							family: 6,
							addr: addr.address,
							mask: to_mask(addr.mask, true),
							bits: addr.mask
						});
					}
				}

				if (type(ifc["ipv6-prefix-assignment"]) == "array") {
					for (let addr in ifc["ipv6-prefix-assignment"]) {
						if (addr["local-address"]) {
							push(net.ipaddrs ||= [], {
								family: 6,
								addr: addr["local-address"].address,
								mask: to_mask(addr["local-address"].mask, true),
								bits: addr["local-address"].mask
							});
						}
					}
				}

				if (type(ifc.data?.firewall) == "array") {
					let n = 0;

					for (let rulespec in ifc.data.firewall) {
						push(rules, {
							...rulespec,

							name: (rulespec.type != 'ipset') ? `ubus:${ifc.interface}[${ifc.proto}] ${rulespec.type || 'rule'} ${n}` : rulespec.name,
							device: rulespec.device || ifc.l3_device
						});

						n++;
					}
				}

				networks[ifc.interface] = net;
			}
		}


		//
		// Gather firewall rule definitions from ubus services
		//

		if (type(services) == "object") {
			for (let svcname, service in services) {
				if (type(service?.firewall) == "array") {
					let n = 0;

					for (let rulespec in services[svcname].firewall) {
						push(rules, {
							...rulespec,

							name: (rulespec.type != 'ipset') ? `ubus:${svcname} ${rulespec.type || 'rule'} ${n}` : rulespec.name
						});

						n++;
					}
				}

				for (let svcinst, instance in service) {
					if (type(instance?.firewall) == "array") {
						let n = 0;

						for (let rulespec in instance.firewall) {
							push(rules, {
								...rulespec,

								name: (rulespec.type != 'ipset') ? `ubus:${svcname}[${svcinst}] ${rulespec.type || 'rule'} ${n}` : rulespec.name
							});

							n++;
						}
					}
				}
			}
		}

		return {
			networks: networks,
			ubus_rules: rules
		};
	},

	load: function(use_statefile) {
		let self = this;

		this.state = use_statefile ? this.read_state() : null;

		this.cursor = uci.cursor();
		this.cursor.load("firewall");
		this.cursor.load("/usr/share/firewall4/helpers");

		if (!this.state)
			this.state = this.read_ubus();

		this.kernel = this.read_kernel_version();


		//
		// Read helper mapping
		//

		this.cursor.foreach("helpers", "helper", h => self.parse_helper(h));


		//
		// Read default policies
		//

		this.cursor.foreach("firewall", "defaults", d => self.parse_defaults(d));

		if (!this.state.defaults)
			this.parse_defaults({});


		//
		// Build list of ipsets
		//

		if (!this.state.ipsets) {
			map(filter(this.state.ubus_rules, n => (n.type == "ipset")), s => self.parse_ipset(s));
			this.cursor.foreach("firewall", "ipset", s => self.parse_ipset(s));
		}


		//
		// Build list of logical zones
		//

		if (!this.state.zones)
			this.cursor.foreach("firewall", "zone", z => self.parse_zone(z));


		//
		// Build list of rules
		//

		map(filter(this.state.ubus_rules, r => (r.type == "rule")), r => self.parse_rule(r));
		this.cursor.foreach("firewall", "rule", r => self.parse_rule(r));


		//
		// Build list of forwardings
		//

		this.cursor.foreach("firewall", "forwarding", f => self.parse_forwarding(f));


		//
		// Build list of redirects
		//

		map(filter(this.state.ubus_rules, r => (r.type == "redirect")), r => self.parse_redirect(r));
		this.cursor.foreach("firewall", "redirect", r => self.parse_redirect(r));


		//
		// Build list of snats
		//

		map(filter(this.state.ubus_rules, n => (n.type == "nat")), n => self.parse_nat(n));
		this.cursor.foreach("firewall", "nat", n => self.parse_nat(n));


		if (use_statefile) {
			let fd = fs.open(STATEFILE, "w");

			if (fd) {
				fd.write({
					zones: this.state.zones,
					ipsets: this.state.ipsets,
					networks: this.state.networks,
					ubus_rules: this.state.ubus_rules
				});

				fd.close();
			}
			else {
				warn(`Unable to write '${STATEFILE}': ${fs.error()}\n`);
			}
		}
	},

	warn: function(fmt, ...args) {
		if (getenv("QUIET"))
			return;

		let msg = sprintf(fmt, ...args);

		if (getenv("TTY"))
			warn(`\033[33m${msg}\033[m\n`);
		else
			warn(`[!] ${msg}\n`);
	},

	get: function(sid, opt) {
		return this.cursor.get("firewall", sid, opt);
	},

	get_all: function(sid) {
		return this.cursor.get_all("firewall", sid);
	},

	parse_options: function(s, spec) {
		let rv = {};

		for (let key, val in spec) {
			let datatype = `parse_${val[0]}`,
			    defval = val[1],
			    flags = val[2] || 0,
			    parsefn = (flags & PARSE_LIST) ? "parse_list" : "parse_opt";

			let res = this[parsefn](s, key, datatype, defval, flags);

			if (res !== res)
				return false;

			if (type(res) == "object" && res.invert && (flags & NO_INVERT)) {
				this.warn_section(s, `option '${key}' must not be negated`);
				return false;
			}

			if (res != null) {
				if (flags & DEPRECATED)
					this.warn_section(s, `option '${key}' is deprecated by fw4`);
				else if (flags & UNSUPPORTED)
					this.warn_section(s, `option '${key}' is not supported by fw4`);
				else
					rv[key] = res;
			}
		}

		for (let opt in s) {
			if (index(opt, '.') != 0 && opt != 'type' && !exists(spec, opt)) {
				this.warn_section(s, `specifies unknown option '${opt}'`);
			}
		}

		return rv;
	},

	parse_subnet: function(subnet) {
		let parts = split(subnet, "/");
		let a, b, m, n;

		switch (length(parts)) {
		case 2:
			a = iptoarr(parts[0]);
			m = iptoarr(parts[1]);

			if (!a)
				return null;

			if (m) {
				if (length(a) != length(m))
					return null;

				b = to_bits(parts[1]);

				/* allow non-contiguous masks such as `::ffff:ffff:ffff:ffff` */
				if (b == null) {
					b = -1;

					for (let i, x in m)
						a[i] &= x;
				}

				m = arrtoip(m);
			}
			else {
				b = +parts[1];

				if (type(b) != "int")
					return null;

				m = to_mask(b, length(a) == 16);
				b = max(-1, b);
			}

			return [{
				family: (length(a) == 16) ? 6 : 4,
				addr: arrtoip(a),
				mask: m,
				bits: b
			}];

		case 1:
			parts = split(parts[0], "-");

			switch (length(parts)) {
			case 2:
				a = iptoarr(parts[0]);
				b = iptoarr(parts[1]);

				if (a && b && length(a) == length(b)) {
					return [{
						family: (length(a) == 16) ? 6 : 4,
						addr: arrtoip(a),
						addr2: arrtoip(b),
						range: true
					}];
				}

				break;

			case 1:
				a = iptoarr(parts[0]);

				if (a) {
					return [{
						family: (length(a) == 16) ? 6 : 4,
						addr: arrtoip(a),
						mask: to_mask(length(a) * 8, length(a) == 16),
						bits: length(a) * 8
					}];
				}

				n = this.state.networks[parts[0]];

				if (n)
					return [ ...(n.ipaddrs || []) ];
			}
		}

		return null;
	},

	parse_enum: function(val, choices) {
		if (type(val) == "string") {
			val = lc(val);

			for (let i = 0; i < length(choices); i++)
				if (lc(substr(choices[i], 0, length(val))) == val)
					return choices[i];
		}

		return null;
	},

	section_id: function(sid) {
		let s = this.get_all(sid);

		if (!s)
			return null;

		if (s[".anonymous"]) {
			let c = 0;

			this.cursor.foreach("firewall", s[".type"], function(ss) {
				if (ss[".name"] == s[".name"])
					return false;

				c++;
			});

			return `@${s['.type']}[${c}]`;
		}

		return s[".name"];
	},

	warn_section: function(s, msg) {
		if (s[".name"]) {
			if (s.name)
				this.warn("Section %s (%s) %s", this.section_id(s[".name"]), s.name, msg);
			else
				this.warn("Section %s %s", this.section_id(s[".name"]), msg);
		}
		else {
			if (s.name)
				this.warn("ubus %s (%s) %s", s.type || "rule", s.name, msg);
			else
				this.warn("ubus %s %s", s.type || "rule", msg);
		}
	},

	parse_policy: function(val) {
		return this.parse_enum(val, [
			"accept",
			"reject",
			"drop"
		]);
	},

	parse_bool: function(val) {
		if (val == "1" || val == "on" || val == "true" || val == "yes")
			return true;
		else if (val == "0" || val == "off" || val == "false" || val == "no")
			return false;
		else
			return null;
	},

	parse_family: function(val) {
		if (val == 'any' || val == 'all' || val == '*')
			return 0;
		else if (val == 'inet' || index(val, '4') > -1)
			return 4;
		else if (index(val, '6') > -1)
			return 6;

		return null;
	},

	parse_zone_ref: function(val) {
		if (val == null)
			return null;

		if (val == '*')
			return { any: true };

		for (let zone in this.state.zones) {
			if (zone.name == val) {
				return {
					any: false,
					zone: zone
				};
			}
		}

		return null;
	},

	parse_device: function(val) {
		let rv = this.parse_invert(val);

		if (!rv)
			return null;

		if (rv.val == '*')
			rv.any = true;
		else
			rv.device = rv.val;

		return rv;
	},

	parse_direction: function(val) {
		if (val == 'in' || val == 'ingress')
			return false;
		else if (val == 'out' || val == 'egress')
			return true;

		return null;
	},

	parse_setmatch: function(val) {
		let rv = this.parse_invert(val);

		if (!rv)
			return null;

		rv.val = trim(replace(rv.val, /^[^ \t]+/, function(m) {
			rv.name = m;
			return '';
		}));

		let dir = split(rv.val, /[ \t,]/);

		for (let i = 0; i < 3 && i < length(dir); i++) {
			if (dir[i] == "dst" || dir[i] == "dest")
				(rv.dir ||= [])[i] = "dst";
			else if (dir[i] == "src")
				(rv.dir ||= [])[i] = "src";
		}

		return length(rv.name) ? rv : null;
	},

	parse_cthelper: function(val) {
		let rv = this.parse_invert(val);

		if (!rv)
			return null;

		let helper = filter(this.state.helpers, h => (h.name == rv.val))[0];

		return helper ? { ...rv, ...helper } : null;
	},

	parse_protocol: function(val) {
		let p = this.parse_invert(val);

		if (!p)
			return null;

		p.val = lc(p.val);

		switch (p.val) {
		case 'all':
		case 'any':
		case '*':
			p.any = true;
			break;

		case '1':
		case 'icmp':
			p.name = 'icmp';
			break;

		case '58':
		case 'icmpv6':
		case 'ipv6-icmp':
			p.name = 'ipv6-icmp';
			break;

		case 'tcpudp':
			return [
				{ invert: p.invert, name: 'tcp' },
				{ invert: p.invert, name: 'udp' }
			];

		case '6':
			p.name = 'tcp';
			break;

		case '17':
			p.name = 'udp';
			break;

		default:
			p.name = p.val;
		}

		return (p.any || length(p.name)) ? p : null;
	},

	parse_mac: function(val) {
		let mac = this.parse_invert(val);
		let m = mac ? match(mac.val, /^([0-9a-f]{1,2})[:-]([0-9a-f]{1,2})[:-]([0-9a-f]{1,2})[:-]([0-9a-f]{1,2})[:-]([0-9a-f]{1,2})[:-]([0-9a-f]{1,2})$/i) : null;

		if (!m)
			return null;

		mac.mac = sprintf('%02x:%02x:%02x:%02x:%02x:%02x',
		                  hex(m[1]), hex(m[2]), hex(m[3]),
		                  hex(m[4]), hex(m[5]), hex(m[6]));

		return mac;
	},

	parse_port: function(val) {
		let port = this.parse_invert(val);
		let m = port ? match(port.val, /^([0-9]{1,5})([-:]([0-9]{1,5}))?$/i) : null;

		if (!m)
			return null;

		if (m[3]) {
			let min_port = +m[1];
			let max_port = +m[3];

			if (min_port > max_port ||
			    min_port < 0 || max_port < 0 ||
			    min_port > 65535 || max_port > 65535)
				return null;

			port.min = min_port;
			port.max = max_port;
		}
		else {
			let pn = +m[1];

			if (pn != pn || pn < 0 || pn > 65535)
				return null;

			port.min = pn;
			port.max = pn;
		}

		return port;
	},

	parse_network: function(val) {
		let rv = this.parse_invert(val);

		if (!rv)
			return null;

		let nets = this.parse_subnet(rv.val);

		if (nets === null)
			return null;

		if (length(nets))
			rv.addrs = [ ...nets ];

		return rv;
	},

	parse_icmptype: function(val) {
		let rv = {};

		if (exists(ipv4_icmptypes, val)) {
			rv.family = 4;

			rv.type = ipv4_icmptypes[val][0];
			rv.code_min = ipv4_icmptypes[val][1];
			rv.code_max = ipv4_icmptypes[val][2];
		}

		if (exists(ipv6_icmptypes, val)) {
			rv.family = rv.family ? 0 : 6;

			rv.type6 = ipv6_icmptypes[val][0];
			rv.code6_min = ipv6_icmptypes[val][1];
			rv.code6_max = ipv6_icmptypes[val][2];
		}

		if (!exists(rv, "family")) {
			let m = match(val, /^([0-9]+)(\/([0-9]+))?$/);

			if (!m)
				return null;

			if (m[3]) {
				rv.type = +m[1];
				rv.code_min = +m[3];
				rv.code_max = rv.code_min;
			}
			else {
				rv.type = +m[1];
				rv.code_min = 0;
				rv.code_max = 0xFF;
			}

			if (rv.type > 0xFF || rv.code_min > 0xFF || rv.code_max > 0xFF)
				return null;

			rv.family = 0;

			rv.type6 = rv.type;
			rv.code6_min = rv.code_min;
			rv.code6_max = rv.code_max;
		}

		return rv;
	},

	parse_invert: function(val) {
		if (val == null)
			return null;

		let rv = { invert: false };

		rv.val = trim(replace(val, /^[ \t]*!/, () => (rv.invert = true, '')));

		return length(rv.val) ? rv : null;
	},

	parse_limit: function(val) {
		let rv = this.parse_invert(val);
		let m = rv ? match(rv.val, /^([0-9]+)(\/([a-z]+))?$/) : null;

		if (!m)
			return null;

		let n = +m[1];
		let u = m[3] ? this.parse_enum(m[3], [ "second", "minute", "hour", "day" ]) : "second";

		if (!u)
			return null;

		rv.rate = n;
		rv.unit = u;

		return rv;
	},

	parse_int: function(val) {
		let n = +val;

		return (n == n) ? n : null;
	},

	parse_date: function(val) {
		let d = match(val, /^([0-9]{4})(-([0-9]{1,2})(-([0-9]{1,2})(T([0-9:]+))?)?)?$/);

		if (d == null || d[1] < 1970 || d[1] > 2038 || d[3] > 12 || d[5] > 31)
			return null;

		let t = this.parse_time(d[7] ?? "0");

		if (t == null)
			return null;

		return {
			year:  +d[1],
			month: +d[3] || 1,
			day:   +d[5] || 1,
			...t
		};
	},

	parse_time: function(val) {
		let t = match(val, /^([0-9]{1,2})(:([0-9]{1,2})(:([0-9]{1,2}))?)?$/);

		if (t == null || t[1] > 23 || t[3] > 59 || t[5] > 59)
			return null;

		return {
			hour: +t[1],
			min:  +t[3],
			sec:  +t[5]
		};
	},

	parse_weekdays: function(val) {
		let rv = this.parse_invert(val);

		if (!rv)
			return null;

		for (let day in to_array(rv.val)) {
			day = this.parse_enum(day, [
				"Monday",
				"Tuesday",
				"Wednesday",
				"Thursday",
				"Friday",
				"Saturday",
				"Sunday"
			]);

			if (!day)
				return null;

			(rv.days ||= {})[day] = true;
		}

		rv.days = keys(rv.days);

		return rv.days ? rv : null;
	},

	parse_monthdays: function(val) {
		let rv = this.parse_invert(val);

		if (!rv)
			return null;

		for (let day in to_array(rv.val)) {
			day = +day;

			if (day < 1 || day > 31)
				return null;

			(rv.days ||= [])[day] = true;
		}

		return rv.days ? rv : null;
	},

	parse_mark: function(val) {
		let rv = this.parse_invert(val);
		let m = rv ? match(rv.val, /^(0?x?[0-9a-f]+)(\/(0?x?[0-9a-f]+))?$/i) : null;

		if (!m)
			return null;

		let n = +m[1];

		if (n != n || n > 0xFFFFFFFF)
			return null;

		rv.mark = n;
		rv.mask = 0xFFFFFFFF;

		if (m[3]) {
			n = +m[3];

			if (n != n || n > 0xFFFFFFFF)
				return null;

			rv.mask = n;
		}

		return rv;
	},

	parse_dscp: function(val) {
		let rv = this.parse_invert(val);

		if (!rv)
			return null;

		rv.val = uc(rv.val);

		if (exists(dscp_classes, rv.val)) {
			rv.dscp = dscp_classes[rv.val];
		}
		else {
			let n = +rv.val;

			if (n != n || n < 0 || n > 0x3F)
				return null;

			rv.dscp = n;
		}

		return rv;
	},

	parse_target: function(val) {
		return this.parse_enum(val, [
			"accept",
			"reject",
			"drop",
			"notrack",
			"helper",
			"mark",
			"dscp",
			"dnat",
			"snat",
			"masquerade",
			"fullcone",
			"accept",
			"reject",
			"drop"
		]);
	},

	parse_reject_code: function(val) {
		return this.parse_enum(val, [
			"tcp-reset",
			"port-unreachable",
			"admin-prohibited",
			"host-unreachable",
			"no-route"
		]);
	},

	parse_reflection_source: function(val) {
		return this.parse_enum(val, [
			"internal",
			"external"
		]);
	},

	parse_ipsettype: function(val) {
		let m = match(val, /^(src|dst|dest)_(.+)$/);
		let t = this.parse_enum(m ? m[2] : val, [
			"ip",
			"port",
			"mac",
			"net",
			"set"
		]);

		return t ? [ (!m || m[1] == 'src') ? 'src' : 'dst', t ] : null;
	},

	parse_ipsetentry: function(val, set) {
		let values = split(val, /[ \t]+/);

		if (length(values) != length(set.types))
			return null;

		let rv = [];
		let ip, mac, port;

		for (let i, t in set.types) {
			switch (t) {
			case 'ipv4_addr':
				ip = filter(this.parse_subnet(values[i]), a => (a.family == 4));

				switch (length(ip) ?? 0) {
				case 0: return null;
				case 1: break;
				default: this.warn("Set entry '%s' resolves to multiple addresses, using first one", values[i]);
				}

				rv[i] = ("net" in set.fw4types) ? `${ip[0].addr}/${ip[0].bits}` : ip[0].addr;
				break;

			case 'ipv6_addr':
				ip = filter(this.parse_subnet(values[i]), a => (a.family == 6));

				switch(length(ip)) {
				case 0: return null;
				case 1: break;
				case 2: this.warn("Set entry '%s' resolves to multiple addresses, using first one", values[i]);
				}

				rv[i] = ("net" in set.fw4types) ? `${ip[0].addr}/${ip[0].bits}` : ip[0].addr;

				break;

			case 'ether_addr':
				mac = this.parse_mac(values[i]);

				if (!mac || mac.invert)
					return null;

				rv[i] = mac.mac;
				break;

			case 'inet_service':
				port = this.parse_port(values[i]);

				if (!port || port.invert || port.min != port.max)
					return null;

				rv[i] = port.min;
				break;

			default:
				rv[i] = values[i];
			}
		}

		return length(rv) ? rv : null;
	},

	parse_string: function(val) {
		return "" + val;
	},

	parse_opt: function(s, opt, fn, defval, flags) {
		let val = s[opt];

		if (val === null) {
			if (flags & REQUIRED) {
				this.warn_section(s, `option '${opt}' is mandatory but not set`);
				return NaN;
			}

			val = defval;
		}

		if (type(val) == "array") {
			this.warn_section(s, `option '${opt}' must not be a list`);
			return NaN;
		}
		else if (val == null) {
			return null;
		}

		let res = this[fn](val);

		if (res === null) {
			this.warn_section(s, `option '${opt}' specifies invalid value '${val}'`);
			return NaN;
		}

		return res;
	},

	parse_list: function(s, opt, fn, defval, flags) {
		let val = s[opt];
		let rv = [];

		if (val == null) {
			if (flags & REQUIRED) {
				this.warn_section(s, `option '${opt}' is mandatory but not set`);
				return NaN;
			}

			val = defval;
		}

		for (val in to_array(val)) {
			let res = this[fn](val);

			if (res === null) {
				this.warn_section(s, `option '${opt}' specifies invalid value '${val}'`);
				return NaN;
			}

			if (flags & FLATTEN_LIST)
				push(rv, ...to_array(res));
			else
				push(rv, res);
		}

		return length(rv) ? rv : null;
	},

	quote: function(s, force) {
		if (force === true || !match(s, /^([0-9A-Fa-f:.\/-]+)( \. [0-9A-Fa-f:.\/-]+)*$/))
			return `"${replace(s + "", /(["\\])/g, '\\$1')}"`;

		return s;
	},

	cidr: function(a) {
		if (a.range)
			return `${a.addr}-${a.addr2}`;

		if ((a.family == 4 && a.bits == 32) ||
		    (a.family == 6 && a.bits == 128))
		    return a.addr;

		if (a.bits >= 0)
			return `${apply_mask(a.addr, a.bits)}/${a.bits}`;

		return `${a.addr}/${a.mask}`;
	},

	host: function(a, v6brackets) {
		return a.range
			? `${a.addr}-${a.addr2}`
			: (a.family == 6 && v6brackets)
				? `[${apply_mask(a.addr, a.bits)}]` : apply_mask(a.addr, a.bits);
	},

	port: function(p) {
		if (p.min == p.max)
			return `${p.min}`;

		return `${p.min}-${p.max}`;
	},

	set: function(v, force) {
		let seen = {};

		v = filter(to_array(v), item => !seen[item]++);

		if (force || length(v) != 1)
			return `{ ${join(', ', map(v, this.quote))} }`;

		return this.quote(v[0]);
	},

	concat: function(v) {
		return join(' . ', to_array(v));
	},

	ipproto: function(family) {
		switch (family) {
		case 4:
			return "ip";

		case 6:
			return "ip6";
		}
	},

	nfproto: function(family, human_readable) {
		switch (family) {
		case 4:
			return human_readable ? "IPv4" : "ipv4";

		case 6:
			return human_readable ? "IPv6" : "ipv6";

		default:
			return human_readable ? "IPv4/IPv6" : null;
		}
	},

	l4proto: function(family, proto) {
		switch (proto.name) {
		case 'icmp':
			switch (family ?? 0) {
			case 0:
				return this.set(['icmp', 'ipv6-icmp']);

			case 6:
				return 'ipv6-icmp';
			}

		default:
			return proto.name;
		}
	},

	datetime: function(stamp) {
		return sprintf('"%04d-%02d-%02d %02d:%02d:%02d"',
		               stamp.year, stamp.month, stamp.day,
		               stamp.hour, stamp.min, stamp.sec);
	},

	date: function(stamp) {
		return sprintf('"%04d-%02d-%02d"', stamp.year, stamp.month, stamp.day);
	},

	datestamp: function(stamp) {
		return exists(stamp, 'hour') ? this.datetime(stamp) : this.date(stamp);
	},

	time: function(stamp) {
		return sprintf('"%02d:%02d:%02d"', stamp.hour, stamp.min, stamp.sec);
	},

	hex: function(n) {
		return sprintf('0x%x', n);
	},

	is_loopback_dev: function(dev) {
		let fd = fs.open(`/sys/class/net/${dev}/flags`, "r");

		if (!fd)
			return false;

		let flags = +fd.read("line");

		fd.close();

		return !!(flags & 0x8);
	},

	is_loopback_addr: function(addr) {
		return (index(addr, "127.") == 0 || addr == "::1" || addr == "::1/128");
	},

	filter_loopback_devs: function(devs, invert) {
		return null_if_empty(filter(devs, d => (this.is_loopback_dev(d) == invert)));
	},

	filter_loopback_addrs: function(addrs, invert) {
		return null_if_empty(filter(addrs, a => (this.is_loopback_addr(a) == invert)));
	},


	input_policy: function(reject_as_drop) {
		return (!reject_as_drop || this.state.defaults.input != 'reject') ? this.state.defaults.input : 'drop';
	},

	output_policy: function(reject_as_drop) {
		return (!reject_as_drop || this.state.defaults.output != 'reject') ? this.state.defaults.output : 'drop';
	},

	forward_policy: function(reject_as_drop) {
		return (!reject_as_drop || this.state.defaults.forward != 'reject') ? this.state.defaults.forward : 'drop';
	},

	default_option: function(flag) {
		return this.state.defaults[flag];
	},

	helpers: function() {
		return this.state.helpers;
	},

	zones: function() {
		return this.state.zones;
	},

	rules: function(chain) {
		return filter(this.state.rules, r => (r.chain == chain));
	},

	redirects: function(chain) {
		return filter(this.state.redirects, r => (r.chain == chain));
	},

	ipsets: function() {
		return this.state.ipsets;
	},

	parse_setfile: function(set, cb) {
		let fd = fs.open(set.loadfile, "r");

		if (!fd) {
			warn(`Unable to load file '${set.loadfile}' for set '${set.name}': ${fs.error()}\n`);
			return;
		}

		let line = null, count = 0;

		while ((line = fd.read("line")) !== "") {
			line = trim(line);

			if (length(line) == 0 || ord(line) == 35)
				continue;

			let v = this.parse_ipsetentry(line, set);

			if (!v) {
				this.warn(`Skipping invalid entry '${line}' in file '${set.loadfile}' for set '${set.name}'`);
				continue;
			}

			cb(v);

			count++;
		}

		fd.close();

		return count;
	},

	print_setentries: function(set) {
		let first = true;
		let printer = (entry) => {
			if (first) {
				print("\t\telements = {\n");
				first = false;
			}

			print("\t\t\t", join(" . ", entry), ",\n");
		};

		map(set.entries, printer);

		if (set.loadfile)
			this.parse_setfile(set, printer);

		if (!first)
			print("\t\t}\n");
	},

	parse_helper: function(data) {
		let helper = this.parse_options(data, {
			name: [ "string", null, REQUIRED ],
			description: [ "string" ],
			module: [ "string" ],
			family: [ "family" ],
			proto: [ "protocol", null, PARSE_LIST | FLATTEN_LIST | NO_INVERT ],
			port: [ "port", null, NO_INVERT ]
		});

		if (helper === false) {
			this.warn("Helper definition '%s' skipped due to invalid options", data.name || data['.name']);
			return;
		}
		else if (helper.proto.any) {
			this.warn("Helper definition '%s' must not specify wildcard protocol", data.name || data['.name']);
			return;
		}
		else if (length(helper.proto) > 1) {
			this.warn("Helper definition '%s' must not specify multiple protocols", data.name || data['.name']);
			return;
		}

		helper.available = (fs.stat(`/sys/module/${helper.module}`)?.type == "directory");

		push(this.state.helpers ||= [], helper);
	},

	parse_defaults: function(data) {
		if (this.state.defaults) {
			this.warn_section(data, ": ignoring duplicate defaults section");
			return;
		}

		let defs = this.parse_options(data, {
			fullcone: [ "bool", "0" ],
			input: [ "policy", "drop" ],
			output: [ "policy", "drop" ],
			forward: [ "policy", "drop" ],

			drop_invalid: [ "bool" ],
			tcp_reject_code: [ "reject_code", "tcp-reset" ],
			any_reject_code: [ "reject_code", "port-unreachable" ],

			syn_flood: [ "bool" ],
			synflood_protect: [ "bool" ],
			synflood_rate: [ "limit", "25/second" ],
			synflood_burst: [ "int", "50" ],

			tcp_syncookies: [ "bool", "1" ],
			tcp_ecn: [ "int" ],
			tcp_window_scaling: [ "bool", "1" ],

			accept_redirects: [ "bool" ],
			accept_source_route: [ "bool" ],

			auto_helper: [ "bool", "1" ],
			custom_chains: [ "bool", null, UNSUPPORTED ],
			disable_ipv6: [ "bool", null, UNSUPPORTED ],
			flow_offloading: [ "bool", "0" ],
			flow_offloading_hw: [ "bool", "0" ]
		});

		if (defs.synflood_protect === null)
			defs.synflood_protect = defs.syn_flood;

		delete defs.syn_flood;

		if (!nft_try_fullcone()) {
			delete defs.fullcone;
			warn("nft_try_fullcone failed, disable fullcone globally\n");
		}

		this.state.defaults = defs;
	},

	parse_zone: function(data) {
		let zone = this.parse_options(data, {
			enabled: [ "bool", "1" ],

			name: [ "string", null, REQUIRED ],
			family: [ "family" ],

			network: [ "device", null, PARSE_LIST ],
			device: [ "device", null, PARSE_LIST ],
			subnet: [ "network", null, PARSE_LIST ],

			input: [ "policy", this.state.defaults ? this.state.defaults.input : "drop" ],
			output: [ "policy", this.state.defaults ? this.state.defaults.output : "drop" ],
			forward: [ "policy", this.state.defaults ? this.state.defaults.forward : "drop" ],

			masq: [ "bool" ],
			masq_allow_invalid: [ "bool" ],
			masq_src: [ "network", null, PARSE_LIST ],
			masq_dest: [ "network", null, PARSE_LIST ],

			masq6: [ "bool" ],
			fullcone: [ "bool", "0" ],

			extra: [ "string", null, UNSUPPORTED ],
			extra_src: [ "string", null, UNSUPPORTED ],
			extra_dest: [ "string", null, UNSUPPORTED ],

			mtu_fix: [ "bool" ],
			custom_chains: [ "bool", null, UNSUPPORTED ],

			log: [ "int" ],
			log_limit: [ "limit", null, UNSUPPORTED ],

			auto_helper: [ "bool", "1" ],
			helper: [ "cthelper", null, PARSE_LIST ],

			counter: [ "bool", "1" ]
		});

		if (zone === false) {
			this.warn_section(data, "skipped due to invalid options");
			return;
		}
		else if (!zone.enabled) {
			this.warn_section(data, "is disabled, ignoring section");
			return;
		}
		else if (zone.helper && !zone.helper.available) {
			this.warn_section(data, `uses unavailable ct helper '${zone.helper.name}', ignoring section`);
			return;
		}

		if (this.state.defaults && !this.state.defaults.fullcone) {
			this.warn_section(data, "fullcone in defaults not enabled, ignore zone fullcone setting");
			zone.fullcone = false;
		}
		if (zone.fullcone) {
			this.warn_section(data, "fullcone enabled for zone '" + zone.name + "'");
		}

		if (zone.mtu_fix && this.kernel < 0x040a0000) {
			this.warn_section(data, "option 'mtu_fix' requires kernel 4.10 or later");
			return;
		}

		if (this.state.defaults?.auto_helper === false)
			zone.auto_helper = false;

		let match_devices = [];
		let related_physdevs = [];
		let related_subnets = [];
		let related_ubus_networks = [];
		let match_subnets, masq_src_subnets, masq_dest_subnets;

		for (let name, net in this.state.networks) {
			if (net.zone === zone.name)
				push(related_ubus_networks, { invert: false, device: name });
		}

		zone.network = [ ...to_array(zone.network), ...related_ubus_networks ];

		for (let e in zone.network) {
			if (exists(this.state.networks, e.device)) {
				let net = this.state.networks[e.device];

				if (net.device) {
					push(match_devices, {
						invert: e.invert,
						device: net.device
					});
				}

				if (net.physdev && !e.invert)
					push(related_physdevs, net.physdev);

				push(related_subnets, ...(net.ipaddrs || []));
			}
		}

		push(match_devices, ...to_array(zone.device));

		match_subnets = subnets_split_af(zone.subnet);
		masq_src_subnets = subnets_split_af(zone.masq_src);
		masq_dest_subnets = subnets_split_af(zone.masq_dest);

		push(related_subnets, ...(match_subnets[0] || []), ...(match_subnets[1] || []));

		let match_rules = [];

		let add_rule = (family, devices, subnets, zone) => {
			let r = {};

			r.family = family;

			r.devices_pos = null_if_empty(devices[0]);
			r.devices_neg = null_if_empty(devices[1]);
			r.devices_neg_wildcard = null_if_empty(devices[2]);

			r.subnets_pos = map(subnets[0], this.cidr);
			r.subnets_neg = map(subnets[1], this.cidr);
			r.subnets_masked = subnets[2];

			push(match_rules, r);
		};

		let family = infer_family(zone.family, [
			zone.helper, "ct helper",
			match_subnets, "subnet list"
		]);

		if (type(family) == "string") {
			this.warn_section(data, `${family}, skipping`);
			return;
		}

		// group non-inverted device matches into wildcard and non-wildcard ones
		let devices = [], plain_devices = [], plain_invert_devices = [], wildcard_invert_devices = [];

		for (let device in match_devices) {
			let m = match(device.device, /^([^+]*)(\+)?$/);

			if (!m) {
				this.warn_section(data, `skipping invalid wildcard pattern '${device.device}'`);
				continue;
			}

			// filter `+` (match any device) since nftables does not support
			// wildcard only matches
			if (!device.invert && m[0] == '+')
				continue;

			// replace inverted `+` (match no device) with invalid pattern
			if (device.invert && m[0] == '+') {
				device.device = '/never/';
				device.invert = false;
			}

			// replace "name+" matches with "name*"
			else if (m[2] == '+')
				device.device = m[1] + '*';

			device.wildcard = !!m[2];

			if (!device.invert && device.wildcard)
				push(devices, [ [ device.device ], plain_invert_devices, wildcard_invert_devices ]);
			else if (!device.invert)
				push(plain_devices, device.device);
			else if (device.wildcard)
				push(wildcard_invert_devices, device.device);
			else
				push(plain_invert_devices, device.device);
		}

		if (length(plain_devices))
			push(devices, [
				plain_devices,
				plain_invert_devices,
				wildcard_invert_devices
			]);
		else if (!length(devices))
			push(devices, [
				null,
				plain_invert_devices,
				wildcard_invert_devices
			]);

		// emit zone jump rules for each device group
		if (length(match_devices) || length(match_subnets[0]) || length(match_subnets[1])) {
			for (let devgroup in devices) {
				// check if there's no AF specific bits, in this case we can do AF agnostic matching
				if (!family && !length(match_subnets[0]) && !length(match_subnets[1])) {
					add_rule(0, devgroup, [], zone);
				}

				// we need to emit one or two AF specific rules
				else {
					if (!family || family == 4)
						for (let subnets in subnets_group_by_masking(match_subnets[0]))
							add_rule(4, devgroup, subnets, zone);

					if (!family || family == 6)
						for (let subnets in subnets_group_by_masking(match_subnets[1]))
							add_rule(6, devgroup, subnets, zone);
				}
			}
		}

		zone.family = family;

		zone.match_rules = match_rules;

		zone.masq4_src_subnets = subnets_group_by_masking(masq_src_subnets[0]);
		zone.masq4_dest_subnets = subnets_group_by_masking(masq_dest_subnets[0]);

		zone.masq6_src_subnets = subnets_group_by_masking(masq_src_subnets[1]);
		zone.masq6_dest_subnets = subnets_group_by_masking(masq_dest_subnets[1]);

		zone.sflags = {};
		zone.sflags[zone.input] = true;

		zone.dflags = {};
		zone.dflags[zone.output] = true;
		zone.dflags[zone.forward] = true;

		zone.match_devices = map(filter(match_devices, d => !d.invert), d => d.device);
		zone.match_subnets = map(filter(related_subnets, s => !s.invert && s.bits != -1), this.cidr);

		zone.related_subnets = related_subnets;
		zone.related_physdevs = related_physdevs;

		if (zone.fullcone) {
			zone.dflags.snat = true;
			zone.dflags.dnat = true;
		}

		if (zone.masq || zone.masq6)
			zone.dflags.snat = true;

		if ((zone.auto_helper && !(zone.masq || zone.masq6 || zone.fullcone)) || length(zone.helper)) {
			zone.dflags.helper = true;

			for (let helper in (length(zone.helper) ? zone.helper : this.state.helpers)) {
				if (!helper.available)
					continue;

				for (let proto in helper.proto) {
					push(this.state.rules ||= [], {
						chain: `helper_${zone.name}`,
						family: helper.family,
						name: helper.description || helper.name,
						proto: proto,
						src: zone,
						dports_pos: [ this.port(helper.port) ],
						target: "helper",
						set_helper: helper
					});
				}
			}
		}

		push(this.state.zones ||= [], zone);
	},

	parse_forwarding: function(data) {
		let fwd = this.parse_options(data, {
			enabled: [ "bool", "1" ],

			name: [ "string" ],
			family: [ "family" ],

			src: [ "zone_ref", null, REQUIRED ],
			dest: [ "zone_ref", null, REQUIRED ]
		});

		if (fwd === false) {
			this.warn_section(data, "skipped due to invalid options");
			return;
		}
		else if (!fwd.enabled) {
			this.warn_section(data, "is disabled, ignoring section");
			return;
		}

		let add_rule = (family, fwd) => {
			let f = {
				...fwd,

				family: family,
				proto: { any: true }
			};

			f.name ||= `Accept ${fwd.src.any ? "any" : fwd.src.zone.name} to ${fwd.dest.any ? "any" : fwd.dest.zone.name} ${family ? `${this.nfproto(family, true)} ` : ''}forwarding`;
			f.chain = fwd.src.any ? "forward" : `forward_${fwd.src.zone.name}`;

			if (fwd.dest.any)
				f.target = "accept";
			else
				f.jump_chain = `accept_to_${fwd.dest.zone.name}`;

			push(this.state.rules ||= [], f);
		};


		/* inherit family restrictions from related zones */
		let family = infer_family(fwd.family, [
			fwd.src?.zone, "source zone",
			fwd.dest?.zone, "destination zone"
		]);

		if (type(family) == "string") {
			this.warn_section(data, `${family}, skipping`);
			return;
		}

		add_rule(family, fwd);

		if (fwd.dest.zone)
			fwd.dest.zone.dflags.accept = true;
	},

	parse_rule: function(data) {
		let rule = this.parse_options(data, {
			enabled: [ "bool", "1" ],

			name: [ "string", this.section_id(data[".name"]) ],
			_name: [ "string", null, DEPRECATED ],
			family: [ "family" ],

			src: [ "zone_ref" ],
			dest: [ "zone_ref" ],

			device: [ "device", null, NO_INVERT ],
			direction: [ "direction" ],

			ipset: [ "setmatch" ],
			helper: [ "cthelper" ],
			set_helper: [ "cthelper", null, NO_INVERT ],

			proto: [ "protocol", "tcpudp", PARSE_LIST | FLATTEN_LIST ],

			src_ip: [ "network", null, PARSE_LIST ],
			src_mac: [ "mac", null, PARSE_LIST ],
			src_port: [ "port", null, PARSE_LIST ],

			dest_ip: [ "network", null, PARSE_LIST ],
			dest_port: [ "port", null, PARSE_LIST ],

			icmp_type: [ "icmptype", null, PARSE_LIST ],
			extra: [ "string", null, UNSUPPORTED ],

			limit: [ "limit" ],
			limit_burst: [ "int" ],

			utc_time: [ "bool" ],
			start_date: [ "date" ],
			stop_date: [ "date" ],
			start_time: [ "time" ],
			stop_time: [ "time" ],
			weekdays: [ "weekdays" ],
			monthdays: [ "monthdays", null, UNSUPPORTED ],

			mark: [ "mark" ],
			set_mark: [ "mark", null, NO_INVERT ],
			set_xmark: [ "mark", null, NO_INVERT ],

			dscp: [ "dscp" ],
			set_dscp: [ "dscp", null, NO_INVERT ],

			counter: [ "bool", "1" ],

			target: [ "target" ]
		});

		if (rule === false) {
			this.warn_section(data, "skipped due to invalid options");
			return;
		}
		else if (!rule.enabled) {
			this.warn_section(data, "is disabled, ignoring section");
			return;
		}

		if (rule.target in ["helper", "notrack"] && (!rule.src || !rule.src.zone)) {
			this.warn_section(data, `must specify a source zone for target '${rule.target}'`);
			return;
		}
		else if (rule.target == "dscp" && !rule.set_dscp) {
			this.warn_section(data, "must specify option 'set_dscp' for target 'dscp'");
			return;
		}
		else if (rule.target == "mark" && !rule.set_mark && !rule.set_xmark) {
			this.warn_section(data, "must specify option 'set_mark' or 'set_xmark' for target 'mark'");
			return;
		}
		else if (rule.target == "helper" && !rule.set_helper) {
			this.warn_section(data, "must specify option 'set_helper' for target 'helper'");
			return;
		}
		else if (rule.device?.any) {
			this.warn_section(data, "must not specify '*' as device");
			return;
		}

		let ipset;

		if (rule.ipset) {
			ipset = filter(this.state.ipsets, s => (s.name == rule.ipset.name))[0];

			if (!ipset) {
				this.warn_section(data, `references unknown set '${rule.ipset.name}'`);
				return;
			}

			if (('inet_service' in ipset.types) && !ensure_tcpudp(rule.proto)) {
				this.warn_section(data, "references named set with port match but no UDP/TCP protocol, ignoring section");
				return;
			}
		}

		let need_src_action_chain = (rule) => (rule.src?.zone?.log && rule.target != "accept");

		let add_rule = (family, proto, saddrs, daddrs, sports, dports, icmptypes, icmpcodes, ipset, rule) => {
			let r = {
				...rule,

				family: family,
				proto: proto,
				has_addrs: !!(saddrs[0] || saddrs[1] || saddrs[2] || daddrs[0] || daddrs[1] || daddrs[2]),
				has_ports: !!(length(sports) || length(dports)),
				saddrs_pos: map(saddrs[0], this.cidr),
				saddrs_neg: map(saddrs[1], this.cidr),
				saddrs_masked: saddrs[2],
				daddrs_pos: map(daddrs[0], this.cidr),
				daddrs_neg: map(daddrs[1], this.cidr),
				daddrs_masked: daddrs[2],
				sports_pos: map(filter_pos(sports), this.port),
				sports_neg: map(filter_neg(sports), this.port),
				dports_pos: map(filter_pos(dports), this.port),
				dports_neg: map(filter_neg(dports), this.port),
				smacs_pos: map(filter_pos(rule.src_mac), m => m.mac),
				smacs_neg: map(filter_neg(rule.src_mac), m => m.mac),
				icmp_types: map(icmptypes, i => (family == 4 ? i.type : i.type6)),
				icmp_codes: map(icmpcodes, ic => `${(family == 4) ? ic.type : ic.type6} . ${(family == 4) ? ic.code_min : ic.code6_min}`)
			};

			if (!length(r.icmp_types))
				delete r.icmp_types;

			if (!length(r.icmp_codes))
				delete r.icmp_codes;

			if (r.set_mark) {
				r.set_xmark = {
					invert: r.set_mark.invert,
					mark:   r.set_mark.mark,
					mask:   r.set_mark.mark | r.set_mark.mask
				};

				delete r.set_mark;
			}

			let set_types = map_setmatch(ipset, rule.ipset, proto.name);

			if (set_types !== set_types) {
				this.warn_section(data, "destination MAC address matching not supported");
				return;
			} else if (set_types) {
				r.ipset = { ...r.ipset, fields: set_types };
			}

			if (r.target == "notrack") {
				r.chain = `notrack_${r.src.zone.name}`;
				r.src.zone.dflags.notrack = true;
			}
			else if (r.target == "helper") {
				r.chain = `helper_${r.src.zone.name}`;
				r.src.zone.dflags.helper = true;
			}
			else if (r.target == "mark" || r.target == "dscp") {
				if ((r.src?.any && r.dest?.any) || (r.src?.zone && r.dest?.zone))
					r.chain = "mangle_forward";
				else if (r.src?.any && r.dest?.zone)
					r.chain = "mangle_postrouting";
				else if (r.src?.zone && r.dest?.any)
					r.chain = "mangle_prerouting";
				else if (r.src && !r.dest)
					r.chain = "mangle_input";
				else
					r.chain = "mangle_output";

				if (r.src?.zone) {
					r.src.zone.dflags[r.target] = true;
					r.iifnames = null_if_empty(r.src.zone.match_devices);
				}

				if (r.dest?.zone) {
					r.dest.zone.dflags[r.target] = true;
					r.oifnames = null_if_empty(r.dest.zone.match_devices);
				}
			}
			else {
				r.chain = "output";

				if (r.src) {
					if (!r.src.any)
						r.chain = `${r.dest ? "forward" : "input"}_${r.src.zone.name}`;
					else
						r.chain = r.dest ? "forward" : "input";
				}

				if (r.dest && !r.src) {
					if (!r.dest.any)
						r.chain = sprintf("output_%s", r.dest.zone.name);
					else
						r.chain = "output";
				}

				if (r.dest && !r.dest.any) {
					r.jump_chain = `${r.target}_to_${r.dest.zone.name}`;
					r.dest.zone.dflags[r.target] = true;
				}
				else if (need_src_action_chain(r)) {
					r.jump_chain = `${r.target}_from_${r.src.zone.name}`;
					r.src.zone.sflags[r.target] = true;
				}
				else if (r.target == "reject")
					r.jump_chain = "handle_reject";
			}

			if (r.device)
				r[r.direction ? "oifnames" : "iifnames"] = [ r.device.device ];

			push(this.state.rules ||= [], r);
		};

		for (let proto in rule.proto) {
			let sip, dip, sports, dports, itypes4, itypes6;
			let family = rule.family;

			switch (proto.name) {
			case "icmp":
				itypes4 = filter(rule.icmp_type || [], family_is_ipv4);
				itypes6 = filter(rule.icmp_type || [], family_is_ipv6);
				break;

			case "ipv6-icmp":
				family = 6;
				itypes6 = filter(rule.icmp_type || [], family_is_ipv6);
				break;

			case "tcp":
			case "udp":
				sports = rule.src_port;
				dports = rule.dest_port;
				break;
			}

			sip = subnets_split_af(rule.src_ip);
			dip = subnets_split_af(rule.dest_ip);

			family = infer_family(family, [
				ipset, "set match",
				sip, "source IP",
				dip, "destination IP",
				rule.src?.zone, "source zone",
				rule.dest?.zone, "destination zone",
				rule.helper, "helper match",
				rule.set_helper, "helper to set"
			]);

			if (type(family) == "string") {
				this.warn_section(data, `${family}, skipping`);
				continue;
			}

			let has_ipv4_specifics = (length(sip[0]) || length(dip[0]) || length(itypes4) || rule.dscp !== null);
			let has_ipv6_specifics = (length(sip[1]) || length(dip[1]) || length(itypes6) || rule.dscp !== null);

			/* if no family was configured, infer target family from IP addresses */
			if (family === null) {
				if (has_ipv4_specifics && !has_ipv6_specifics)
					family = 4;
				else if (has_ipv6_specifics && !has_ipv4_specifics)
					family = 6;
				else
					family = 0;
			}

			/* check if there's no AF specific bits, in this case we can do an AF agnostic rule */
			if (!family && rule.target != "dscp" && !has_ipv4_specifics && !has_ipv6_specifics) {
				add_rule(0, proto, [], [], sports, dports, null, null, null, rule);
			}

			/* we need to emit one or two AF specific rules */
			else {
				if (family == 0 || family == 4) {
					let icmp_types = filter(itypes4, i => (i.code_min == 0 && i.code_max == 0xFF));
					let icmp_codes = filter(itypes4, i => (i.code_min != 0 || i.code_max != 0xFF));

					for (let saddrs in subnets_group_by_masking(sip[0])) {
						for (let daddrs in subnets_group_by_masking(dip[0])) {
							if (length(icmp_types) || (!length(icmp_types) && !length(icmp_codes)))
								add_rule(4, proto, saddrs, daddrs, sports, dports, icmp_types, null, ipset, rule);

							if (length(icmp_codes))
								add_rule(4, proto, saddrs, daddrs, sports, dports, null, icmp_codes, ipset, rule);
						}
					}
				}

				if (family == 0 || family == 6) {
					let icmp_types = filter(itypes6, i => (i.code_min == 0 && i.code_max == 0xFF));
					let icmp_codes = filter(itypes6, i => (i.code_min != 0 || i.code_max != 0xFF));

					for (let saddrs in subnets_group_by_masking(sip[1])) {
						for (let daddrs in subnets_group_by_masking(dip[1])) {
							if (length(icmp_types) || (!length(icmp_types) && !length(icmp_codes)))
								add_rule(6, proto, saddrs, daddrs, sports, dports, icmp_types, null, ipset, rule);

							if (length(icmp_codes))
								add_rule(6, proto, saddrs, daddrs, sports, dports, null, icmp_codes, ipset, rule);
						}
					}
				}
			}
		}
	},

	parse_redirect: function(data) {
		let redir = this.parse_options(data, {
			enabled: [ "bool", "1" ],

			name: [ "string", this.section_id(data[".name"]) ],
			_name: [ "string", null, DEPRECATED ],
			family: [ "family" ],

			src: [ "zone_ref" ],
			dest: [ "zone_ref" ],

			ipset: [ "setmatch" ],
			helper: [ "cthelper", null, NO_INVERT ],

			proto: [ "protocol", "tcpudp", PARSE_LIST | FLATTEN_LIST ],

			src_ip: [ "network" ],
			src_mac: [ "mac", null, PARSE_LIST ],
			src_port: [ "port" ],

			src_dip: [ "network" ],
			src_dport: [ "port" ],

			dest_ip: [ "network" ],
			dest_port: [ "port" ],

			extra: [ "string", null, UNSUPPORTED ],

			limit: [ "limit" ],
			limit_burst: [ "int" ],

			utc_time: [ "bool" ],
			start_date: [ "date" ],
			stop_date: [ "date" ],
			start_time: [ "time" ],
			stop_time: [ "time" ],
			weekdays: [ "weekdays" ],
			monthdays: [ "monthdays", null, UNSUPPORTED ],

			mark: [ "mark" ],

			reflection: [ "bool", "1" ],
			reflection_src: [ "reflection_source", "internal" ],

			reflection_zone: [ "zone_ref", null, PARSE_LIST ],

			counter: [ "bool", "1" ],

			target: [ "target", "dnat" ]
		});

		if (redir === false) {
			this.warn_section(data, "skipped due to invalid options");
			return;
		}
		else if (!redir.enabled) {
			this.warn_section(data, "is disabled, ignoring section");
			return;
		}

		if (!(redir.target in ["dnat", "snat"])) {
			this.warn_section(data, "has invalid target specified, defaulting to dnat");
			redir.target = "dnat";
		}

		let ipset;

		if (redir.ipset) {
			ipset = filter(this.state.ipsets, s => (s.name == redir.ipset.name))[0];

			if (!ipset) {
				this.warn_section(data, `references unknown set '${redir.ipset.name}'`);
				return;
			}

			if (('inet_service' in ipset.types) && !ensure_tcpudp(redir.proto)) {
				this.warn_section(data, "references named set with port match but no UDP/TCP protocol, ignoring section");
				return;
			}
		}

		let resolve_dest = (redir) => {
			for (let zone in this.state.zones) {
				for (let zone_addr in zone.related_subnets) {
					for (let dest_addr in redir.dest_ip.addrs) {
						if (dest_addr.family != zone_addr.family)
							continue;

						let a = apply_mask(dest_addr.addr, zone_addr.mask);
						let b = apply_mask(zone_addr.addr, zone_addr.mask);

						if (a != b)
							continue;

						redir.dest = {
							any: false,
							zone: zone
						};

						return true;
					}
				}
			}

			return false;
		};

		if (redir.target == "dnat") {
			if (!redir.src)
				return this.warn_section(data, "has no source specified");
			else if (redir.src.any)
				return this.warn_section(data, "must not have source '*' for dnat target");
			else if (redir.dest_ip && redir.dest_ip.invert)
				return this.warn_section(data, "must not specify a negated 'dest_ip' value");
			else if (redir.dest_ip && length(filter(redir.dest_ip.addrs, a => a.bits == -1)))
				return this.warn_section(data, "must not use non-contiguous masks in 'dest_ip'");

			if (!redir.dest && redir.dest_ip && resolve_dest(redir))
				this.warn_section(data, `does not specify a destination, assuming '${redir.dest.zone.name}'`);

			if (!redir.dest_port)
				redir.dest_port = redir.src_dport;

			if (redir.reflection && redir.dest?.zone && redir.src.zone.masq) {
				redir.dest.zone.dflags.accept = true;
				redir.dest.zone.dflags.dnat = true;
				redir.dest.zone.dflags.snat = true;
			}

			if (redir.helper)
				redir.src.zone.dflags.helper = true;

			redir.src.zone.dflags[redir.target] = true;
		}
		else {
			if (!redir.dest)
				return this.warn_section(data, "has no destination specified");
			else if (redir.dest.any)
				return this.warn_section(data, "must not have destination '*' for snat target");
			else if (!redir.src_dip)
				return this.warn_section(data, "has no 'src_dip' option specified");
			else if (redir.src_dip.invert)
				return this.warn_section(data, "must not specify a negated 'src_dip' value");
			else if (length(filter(redir.src_dip.addrs, a => a.bits == -1)))
				return this.warn_section(data, "must not use non-contiguous masks in 'src_dip'");
			else if (redir.src_mac)
				return this.warn_section(data, "must not use 'src_mac' option for snat target");
			else if (redir.helper)
				return this.warn_section(data, "must not use 'helper' option for snat target");

			redir.dest.zone.dflags[redir.target] = true;
		}


		let add_rule = (family, proto, saddrs, daddrs, raddrs, sport, dport, rport, ipset, redir) => {
			let r = {
				...redir,

				family: family,
				proto: proto,
				has_addrs: !!(saddrs[0] || saddrs[1] || saddrs[2] || daddrs[0] || daddrs[1] || daddrs[2]),
				has_ports: !!(sport || dport || rport),
				saddrs_pos: map(saddrs[0], this.cidr),
				saddrs_neg: map(saddrs[1], this.cidr),
				saddrs_masked: saddrs[2],
				daddrs_pos: map(daddrs[0], this.cidr),
				daddrs_neg: map(daddrs[1], this.cidr),
				daddrs_masked: daddrs[2],
				sports_pos: map(filter_pos(to_array(sport)), this.port),
				sports_neg: map(filter_neg(to_array(sport)), this.port),
				dports_pos: map(filter_pos(to_array(dport)), this.port),
				dports_neg: map(filter_neg(to_array(dport)), this.port),
				smacs_pos: map(filter_pos(redir.src_mac), m => m.mac),
				smacs_neg: map(filter_neg(redir.src_mac), m => m.mac),

				raddr: raddrs ? raddrs[0] : null,
				rport: rport
			};

			let set_types = map_setmatch(ipset, redir.ipset, proto.name);

			if (set_types !== set_types) {
				this.warn_section(data, "destination MAC address matching not supported");
				return;
			} else if (set_types) {
				r.ipset = { ...r.ipset, fields: set_types };
			}

			switch (r.target) {
			case "dnat":
				r.chain = `dstnat_${r.src.zone.name}`;
				r.src.zone.dflags.dnat = true;

				if (!r.raddr)
					r.target = "redirect";

				break;

			case "snat":
				r.chain = `srcnat_${r.dest.zone.name}`;
				r.dest.zone.dflags.snat = true;
				break;
			}

			push(this.state.redirects ||= [], r);
		};

		let to_hostaddr = (a) => {
			let bits = (a.family == 4) ? 32 : 128;

			return {
				family: a.family,
				addr: apply_mask(a.addr, bits),
				bits: bits
			};
		};

		for (let proto in redir.proto) {
			let sip, dip, rip, iip, eip, refip, sport, dport, rport;
			let family = redir.family;

			if (proto.name == "ipv6-icmp")
				family = 6;

			switch (redir.target) {
			case "dnat":
				sip = subnets_split_af(redir.src_ip);
				dip = subnets_split_af(redir.src_dip);
				rip = subnets_split_af(redir.dest_ip);

				switch (proto.name) {
				case "tcp":
				case "udp":
					sport = redir.src_port;
					dport = redir.src_dport;
					rport = redir.dest_port;
					break;
				}

				break;

			case "snat":
				sip = subnets_split_af(redir.src_ip);
				dip = subnets_split_af(redir.dest_ip);
				rip = subnets_split_af(redir.src_dip);

				switch (proto.name) {
				case "tcp":
				case "udp":
					sport = redir.src_port;
					dport = redir.dest_port;
					rport = redir.src_dport;
					break;
				}

				break;
			}

			family = infer_family(family, [
				ipset, "set match",
				sip, "source IP",
				dip, "destination IP",
				rip, "rewrite IP",
				redir.src?.zone, "source zone",
				redir.dest?.zone, "destination zone",
				redir.helper, "helper match"
			]);

			if (type(family) == "string") {
				this.warn_section(data, `${family}, skipping`);
				continue;
			}

			/* build reflection rules */
			if (redir.target == "dnat" && redir.reflection &&
			    (length(rip[0]) || length(rip[1])) && redir.src?.zone && redir.dest?.zone) {
				let refredir = {
					name: `${redir.name} (reflection)`,

					helper: redir.helper,

					// XXX: this likely makes no sense for reflection rules
					//src_mac: redir.src_mac,

					limit: redir.limit,
					limit_burst: redir.limit_burst,

					start_date: redir.start_date,
					stop_date: redir.stop_date,
					start_time: redir.start_time,
					stop_time: redir.stop_time,
					weekdays: redir.weekdays,

					mark: redir.mark
				};

				let eaddrs = length(dip) ? dip : subnets_split_af({ addrs: map(redir.src.zone.related_subnets, to_hostaddr) });
				let rzones = length(redir.reflection_zone) ? redir.reflection_zone : [ redir.dest ];

				for (let rzone in rzones) {
					if (!is_family(rzone, family)) {
						this.warn_section(data,
							`is restricted to IPv${family} but referenced reflection zone is IPv${rzone.family} only, skipping`);
						continue;
					}

					let iaddrs = subnets_split_af({ addrs: rzone.zone.related_subnets });
					let refaddrs = (redir.reflection_src == "internal") ? iaddrs : eaddrs;

					for (let i = 0; i <= 1; i++) {
						if (redir.src.zone[i ? "masq6" : "masq"] && length(rip[i])) {
							let snat_addr = refaddrs[i]?.[0];

							/* For internal reflection sources try to find a suitable candiate IP
							 * among the reflection zone subnets which is within the same subnet
							 * as the original DNAT destination. If we can't find any matching
							 * one then simply take the first candidate. */
							if (redir.reflection_src == "internal") {
								for (let zone_addr in rzone.zone.related_subnets) {
									if (zone_addr.family != rip[i][0].family)
										continue;

									let r = apply_mask(rip[i][0].addr, zone_addr.mask);
									let a = apply_mask(zone_addr.addr, zone_addr.mask);

									if (r != a)
										continue;

									snat_addr = zone_addr;
									break;
								}
							}

							if (!snat_addr) {
								this.warn_section(data, `${redir.reflection_src || "external"} rewrite IP cannot be determined, disabling reflection`);
							}
							else if (!length(iaddrs[i])) {
								this.warn_section(data, "internal address range cannot be determined, disabling reflection");
							}
							else if (!length(eaddrs[i])) {
								this.warn_section(data, "external address range cannot be determined, disabling reflection");
							}
							else {
								refredir.src = rzone;
								refredir.dest = null;
								refredir.target = "dnat";

								for (let saddrs in subnets_group_by_masking(iaddrs[i]))
									for (let daddrs in subnets_group_by_masking(eaddrs[i]))
										add_rule(i ? 6 : 4, proto, saddrs, daddrs, rip[i], sport, dport, rport, null, refredir);

								refredir.src = null;
								refredir.dest = rzone;
								refredir.target = "snat";

								for (let daddrs in subnets_group_by_masking(rip[i]))
									for (let saddrs in subnets_group_by_masking(iaddrs[i]))
										add_rule(i ? 6 : 4, proto, saddrs, daddrs, [ to_hostaddr(snat_addr) ], null, rport, null, null, refredir);
							}
						}
					}
				}
			}

			if (length(rip[0]) > 1 || length(rip[1]) > 1)
				this.warn_section(data, "specifies multiple rewrite addresses, using only first one");

			let has_ip4_addr = length(sip[0]) || length(dip[0]) || length(rip[0]),
			    has_ip6_addr = length(sip[1]) || length(dip[1]) || length(rip[1]),
			    has_any_addr = has_ip4_addr || has_ip6_addr;

			/* check if there's no AF specific bits, in this case we can do an AF agnostic rule */
			if (!family && !has_any_addr) {
				/* for backwards compatibility, treat unspecified family as IPv4 unless user explicitly requested any (0) */
				if (family == null)
					family = 4;

				add_rule(family, proto, [], [], null, sport, dport, rport, null, redir);
			}

			/* we need to emit one or two AF specific rules */
			else {
				if ((!family || family == 4) && (!has_any_addr || has_ip4_addr)) {
					for (let saddrs in subnets_group_by_masking(sip[0]))
						for (let daddrs in subnets_group_by_masking(dip[0]))
							add_rule(4, proto, saddrs, daddrs, rip[0], sport, dport, rport, ipset, redir);
				}

				if ((!family || family == 6) && (!has_any_addr || has_ip6_addr)) {
					for (let saddrs in subnets_group_by_masking(sip[1]))
						for (let daddrs in subnets_group_by_masking(dip[1]))
							add_rule(6, proto, saddrs, daddrs, rip[1], sport, dport, rport, ipset, redir);
				}
			}
		}
	},

	parse_nat: function(data) {
		let snat = this.parse_options(data, {
			enabled: [ "bool", "1" ],

			name: [ "string", this.section_id(data[".name"]) ],
			family: [ "family" ],

			src: [ "zone_ref" ],
			device: [ "string" ],

			ipset: [ "setmatch", null, UNSUPPORTED ],

			proto: [ "protocol", "all", PARSE_LIST | FLATTEN_LIST ],

			src_ip: [ "network" ],
			src_port: [ "port" ],

			snat_ip: [ "network", null, NO_INVERT ],
			snat_port: [ "port", null, NO_INVERT ],

			dest_ip: [ "network" ],
			dest_port: [ "port" ],

			extra: [ "string", null, UNSUPPORTED ],

			limit: [ "limit" ],
			limit_burst: [ "int" ],

			connlimit_ports: [ "bool" ],

			utc_time: [ "bool" ],
			start_date: [ "date" ],
			stop_date: [ "date" ],
			start_time: [ "time" ],
			stop_time: [ "time" ],
			weekdays: [ "weekdays" ],
			monthdays: [ "monthdays", null, UNSUPPORTED ],

			mark: [ "mark" ],

			target: [ "target", "masquerade" ]
		});

		if (snat === false) {
			this.warn_section(data, "skipped due to invalid options");
			return;
		}
		else if (!snat.enabled) {
			this.warn_section(data, "is disabled, ignoring section");
			return;
		}

		if (!(snat.target in ["accept", "snat", "masquerade"])) {
			this.warn_section(data, "has invalid target specified, defaulting to masquerade");
			snat.target = "masquerade";
		}

		if (snat.target == "snat" && !snat.snat_ip && !snat.snat_port) {
			this.warn_section(data, "needs either 'snat_ip' or 'snat_port' for target snat, ignoring section");
			return;
		}
		else if (snat.target != "snat" && snat.snat_ip) {
			this.warn_section(data, "must not use 'snat_ip' for non-snat target, ignoring section");
			return;
		}
		else if (snat.target != "snat" && snat.snat_port) {
			this.warn_section(data, "must not use 'snat_port' for non-snat target, ignoring section");
			return;
		}

		if ((snat.snat_port || snat.src_port || snat.dest_port) && !ensure_tcpudp(snat.proto)) {
			this.warn_section(data, "specifies ports but no UDP/TCP protocol, ignoring section");
			return;
		}

		if (snat.snat_ip && length(filter(snat.snat_ip.addrs, a => a.bits == -1 || a.invert))) {
			this.warn_section(data, "must not use inversion or non-contiguous masks in 'snat_ip', ignoring section");
			return;
		}

		let add_rule = (family, proto, saddrs, daddrs, raddrs, sport, dport, rport, snat) => {
			let n = {
				...snat,

				family: family,
				proto: proto,
				has_addrs: !!(saddrs[0] || saddrs[1] || saddrs[2] || daddrs[0] || daddrs[1] || daddrs[2]),
				has_ports: !!(sport || dport),
				saddrs_pos: map(saddrs[0], this.cidr),
				saddrs_neg: map(saddrs[1], this.cidr),
				saddrs_masked: saddrs[2],
				daddrs_pos: map(daddrs[0], this.cidr),
				daddrs_neg: map(daddrs[1], this.cidr),
				daddrs_masked: daddrs[2],
				sports_pos: map(filter_pos(to_array(sport)), this.port),
				sports_neg: map(filter_neg(to_array(sport)), this.port),
				dports_pos: map(filter_pos(to_array(dport)), this.port),
				dports_neg: map(filter_neg(to_array(dport)), this.port),

				raddr: raddrs ? raddrs[0] : null,
				rport: rport,

				chain: snat.src?.zone ? `srcnat_${snat.src.zone.name}` : "srcnat"
			};

			push(this.state.redirects ||= [], n);
		};

		for (let proto in snat.proto) {
			let sip, dip, rip, sport, dport, rport;
			let family = snat.family;

			sip = subnets_split_af(snat.src_ip);
			dip = subnets_split_af(snat.dest_ip);
			rip = subnets_split_af(snat.snat_ip);

			switch (proto.name) {
			case "tcp":
			case "udp":
				sport = snat.src_port;
				dport = snat.dest_port;
				rport = snat.snat_port;
				break;
			}

			if (length(rip[0]) > 1 || length(rip[1]) > 1)
				this.warn_section(data, "specifies multiple rewrite addresses, using only first one");

			family = infer_family(family, [
				sip, "source IP",
				dip, "destination IP",
				rip, "rewrite IP",
				snat.src?.zone, "source zone"
			]);

			if (type(family) == "string") {
				this.warn_section(data, `${family}, skipping`);
				continue;
			}

			if (snat.src?.zone)
				snat.src.zone.dflags.snat = true;

			/* if no family was configured, infer target family from IP addresses */
			if (family === null) {
				if ((length(sip[0]) || length(dip[0]) || length(rip[0])) && !length(sip[1]) && !length(dip[1]) && !length(rip[1]))
					family = 4;
				else if ((length(sip[1]) || length(dip[1]) || length(rip[1])) && !length(sip[0]) && !length(dip[0]) && !length(rip[0]))
					family = 6;
				else
					family = 4; /* default to IPv4 only for backwards compatibility, unless an explict family any was configured */
			}

			/* check if there's no AF specific bits, in this case we can do an AF agnostic rule */
			if (!family && !length(sip[0]) && !length(sip[1]) && !length(dip[0]) && !length(dip[1]) && !length(rip[0]) && !length(rip[1])) {
				add_rule(0, proto, [], [], null, sport, dport, rport, snat);
			}

			/* we need to emit one or two AF specific rules */
			else {
				if (family == 0 || family == 4)
					for (let saddr in subnets_group_by_masking(sip[0]))
						for (let daddr in subnets_group_by_masking(dip[0]))
							add_rule(4, proto, saddr, daddr, rip[0], sport, dport, rport, snat);

				if (family == 0 || family == 6)
					for (let saddr in subnets_group_by_masking(sip[1]))
						for (let daddr in subnets_group_by_masking(dip[1]))
							add_rule(6, proto, saddr, daddr, rip[1], sport, dport, rport, snat);
			}
		}
	},

	parse_ipset: function(data) {
		let ipset = this.parse_options(data, {
			enabled: [ "bool", "1" ],
			reload_set: [ "bool" ],
			counters: [ "bool" ],
			comment: [ "bool" ],

			name: [ "string", null, REQUIRED ],
			family: [ "family", "4" ],

			storage: [ "string", null, UNSUPPORTED ],
			match: [ "ipsettype", null, PARSE_LIST ],

			iprange: [ "string", null, UNSUPPORTED ],
			portrange: [ "string", null, UNSUPPORTED ],

			netmask: [ "int", null, UNSUPPORTED ],
			maxelem: [ "int" ],
			hashsize: [ "int", null, UNSUPPORTED ],
			timeout: [ "int", "-1" ],

			external: [ "string", null, UNSUPPORTED ],

			entry: [ "string", null, PARSE_LIST ],
			loadfile: [ "string" ]
		});

		if (ipset === false) {
			this.warn_section(data, "skipped due to invalid options");
			return;
		}
		else if (!ipset.enabled) {
			this.warn_section(data, "is disabled, ignoring section");
			return;
		}

		if (ipset.family == 0) {
			this.warn_section(data, "must not specify family 'any'");
			return;
		}
		else if (!length(ipset.match)) {
			this.warn_section(data, "has no datatypes assigned");
			return;
		}

		let dirs = map(ipset.match, m => m[0]),
		    types = map(ipset.match, m => m[1]),
		    interval = false;

		if ("set" in types) {
			this.warn_section(data, "match type 'set' is not supported");
			return;
		}

		if ("net" in types) {
			if (this.kernel < 0x05060000) {
				this.warn_section(data, "match type 'net' requires kernel 5.6 or later");
				return;
			}

			interval = true;
		}

		let s = {
			...ipset,

			fw4types: types,

			types: map(types, (t) => {
				switch (t) {
				case 'ip':
				case 'net':
					return (ipset.family == 4) ? 'ipv4_addr' : 'ipv6_addr';

				case 'mac':
					return 'ether_addr';

				case 'port':
					return 'inet_service';
				}
			}),

			directions: dirs,
			interval: interval
		};

		s.entries = filter(map(ipset.entry, (e) => {
			let v = this.parse_ipsetentry(e, s);

			if (!v)
				this.warn_section(data, `ignoring invalid ipset entry '${e}'`);

			return v;
		}), (e) => (e != null));

		push(this.state.ipsets ||= [], s);
	}
};
