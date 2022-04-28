{%

let fw4 = require("fw4");

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
	    sets = fw4.check_set_types();

	for (let set in state.ipsets) {
		if (!set.loadfile || !length(set.entries))
			continue;

		if (!exists(sets, set.name)) {
			warn(`Named set '${set.name}' does not exist - do you need to restart the firewall?\n`);
			continue;
		}
		else if (fw4.concat(sets[set.name]) != fw4.concat(set.types)) {
			warn(`Named set '${set.name}' has a different type - want '${fw4.concat(set.types)}' but is '${fw4.concat(sets[set.name])}' - do you need to restart the firewall?\n`);
			continue;
		}

		let first = true;
		let printer = (entry) => {
			if (first) {
				print(`add element inet fw4 ${set.name} {\n`);
				first = false;
			}

			print(`	${join(" . ", entry)},\n`);
		};

		print(`flush set inet fw4 ${set.name}\n`);

		map(set.entries, printer);
		fw4.parse_setfile(set, printer);

		if (!first)
			print("}\n\n");
	}
}

function render_ruleset(use_statefile) {
	fw4.load(use_statefile);

	include("templates/ruleset.uc", { fw4, type, exists, length, include });
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
