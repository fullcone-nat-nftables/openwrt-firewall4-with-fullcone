{%

let fw4 = require("fw4");
let ubus = require("ubus");
let fs = require("fs");

/* Find existing sets.
 *
 * Unfortunately, terse mode (-t) is incompatible with JSON output so
 * we either need to parse a potentially huge JSON just to get the set
 * header data or scrape the ordinary nft output to obtain the same
 * information. Opt for the latter to avoid parsing potentially huge
 * JSON documents.
 */
function find_existing_sets() {
	let fd = fs.popen("nft -t list sets inet", "r");

	if (!fd) {
		warn(sprintf("Unable to execute 'nft' for listing existing sets: %s\n",
		             fs.error()));
		return {};
	}

	let line, table, set;
	let sets = {};

	while ((line = fd.read("line")) !== "") {
		let m;

		if ((m = match(line, /^table inet (.+) \{\n$/)) != null) {
			table = m[1];
		}
		else if ((m = match(line, /^\tset (.+) \{\n$/)) != null) {
			set = m[1];
		}
		else if ((m = match(line, /^\t\ttype (.+)\n$/)) != null) {
			if (table == "fw4" && set)
				sets[set] = split(m[1], " . ");

			set = null;
		}
	}

	fd.close();

	return sets;
}

function read_state() {
	let state = fw4.read_state();

	if (!state) {
		warn("Unable to read firewall state - do you need to start the firewall?\n");
		exit(1);
	}

	return state;
}

function reload_sets() {
	let state = read_state(),
	    sets = find_existing_sets();

	for (let set in state.ipsets) {
		if (!set.loadfile || !length(set.entries))
			continue;

		if (!exists(sets, set.name)) {
			warn(sprintf("Named set '%s' does not exist - do you need to restart the firewall?\n",
			             set.name));
			continue;
		}
		else if (fw4.concat(sets[set.name]) != fw4.concat(set.types)) {
			warn(sprintf("Named set '%s' has a different type - want '%s' but is '%s' - do you need to restart the firewall?\n",
			             set.name, fw4.concat(set.types), fw4.concat(sets[set.name])));
			continue;
		}

		let first = true;
		let printer = (entry) => {
			if (first) {
				print("add element inet fw4 ", set.name, " {\n");
				first = false;
			}

			print("\t", join(" . ", entry), ",\n");
		};

		print("flush set inet fw4 ", set.name, "\n");

		map(set.entries, printer);
		fw4.parse_setfile(set, printer);

		if (!first)
			print("}\n\n");
	}
}

function resolve_lower_devices(devstatus, devname) {
	let dir = fs.opendir("/sys/class/net/" + devname);
	let devs = [];

	if (dir) {
		if (!devstatus || devstatus[devname]?.["hw-tc-offload"]) {
			push(devs, devname);
		}
		else {
			let e;

			while ((e = dir.read()) != null)
				if (index(e, "lower_") === 0)
					push(devs, ...resolve_lower_devices(devstatus, substr(e, 6)));
		}

		dir.close();
	}

	return devs;
}

function resolve_offload_devices() {
	if (!fw4.default_option("flow_offloading"))
		return [];

	let devstatus = null;
	let devices = [];

	if (fw4.default_option("flow_offloading_hw")) {
		let bus = require("ubus").connect();

		if (bus) {
			devstatus = bus.call("network.device", "status") || {};
			bus.disconnect();
		}
	}

	for (let zone in fw4.zones())
		for (let device in zone.match_devices)
			push(devices, ...resolve_lower_devices(devstatus, device));

	return uniq(devices);
}

function check_flowtable() {
	let nft = fs.popen("nft --terse --json list flowtables inet");
	let info;

	if (nft) {
		try {
			info = json(nft.read("all"));
		}
		catch (e) {
			info = {};
		}

		nft.close();
	}

	for (let item in info?.nftables)
		if (item?.flowtable?.table == "fw4" && item?.flowtable?.name == "ft")
			return true;

	return false;
}

function render_ruleset(use_statefile) {
	fw4.load(use_statefile);

	include("templates/ruleset.uc", {
		fw4, type, exists, length, include,
		devices: resolve_offload_devices(),
		flowtable: check_flowtable()
	});
}

function lookup_network(net) {
	let state = read_state();

	for (let zone in state.zones) {
		for (let network in (zone.network || [])) {
			if (network.device == net) {
				print(zone.name, "\n");
				exit(0);
			}
		}
	}

	exit(1);
}

function lookup_device(dev) {
	let state = read_state();

	for (let zone in state.zones) {
		for (let rule in (zone.match_rules || [])) {
			if (dev in rule.devices_pos) {
				print(zone.name, "\n");
				exit(0);
			}
		}
	}

	exit(1);
}

function lookup_zone(name, dev) {
	let state = read_state();

	for (let zone in state.zones) {
		if (zone.name == name) {
			let devices = [];
			map(zone.match_rules, (r) => push(devices, ...(r.devices_pos || [])));

			if (dev) {
				if (dev in devices) {
					print(dev, "\n");
					exit(0);
				}

				exit(1);
			}

			if (length(devices))
				print(join("\n", devices), "\n");

			exit(0);
		}
	}

	exit(1);
}


switch (getenv("ACTION")) {
case "start":
	return render_ruleset(true);

case "print":
	return render_ruleset(false);

case "reload-sets":
	return reload_sets();

case "network":
	return lookup_network(getenv("OBJECT"));

case "device":
	return lookup_device(getenv("OBJECT"));

case "zone":
	return lookup_zone(getenv("OBJECT"), getenv("DEVICE"));
}
