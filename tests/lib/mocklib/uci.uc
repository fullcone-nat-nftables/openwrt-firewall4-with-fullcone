let mocklib = global.mocklib;

let byte = (str, off) => {
	let v = ord(str, off);
	return length(v) ? v[0] : v;
};

let hash = (s) => {
	let h = 7;

	for (let i = 0; i < length(s); i++)
		h = h * 31 + byte(s, i);

	return h;
};

let id = (config, t, n) => {
	while (true) {
		let id = sprintf('cfg%08x', hash(t + n));

		if (!exists(config, id))
			return id;

		n++;
	}
};

let fixup_config = (config) => {
	let rv = {};
	let n_section = 0;

	for (let stype in config) {
		switch (type(config[stype])) {
		case 'object':
			config[stype] = [ config[stype] ];
			/* fall through */

		case 'array':
			for (let idx, sobj in config[stype]) {
				let sid, anon;

				if (exists(sobj, '.name') && !exists(rv, sobj['.name'])) {
					sid = sobj['.name'];
					anon = false;
				}
				else {
					sid = id(rv, stype, idx);
					anon = true;
				}

				rv[sid] = {
					'.index': n_section++,
					...sobj,
					'.name': sid,
					'.type': stype,
					'.anonymous': anon
				};
			}

			break;
		}
	}

	for (let n, sid in sort(keys(rv), (a, b) => rv[a]['.index'] - rv[b]['.index']))
		rv[sid]['.index'] = n;

	return rv;
};

return {
	cursor: () => ({
		_configs: {},

		load: function(file) {
			let basename = replace(file, /^.+\//, ''),
			    path = sprintf("uci/%s.json", basename),
			    mock = mocklib.read_json_file(path);

			if (!mock || mock != mock) {
				mocklib.I("No configuration fixture defined for uci package %s.", file);
				mocklib.I("Provide a mock configuration through the following JSON file:\n%s\n", path);

				return null;
			}

			this._configs[basename] = fixup_config(mock);
		},

		_get_section: function(config, section) {
			if (!exists(this._configs, config)) {
				this.load(config);

				if (!exists(this._configs, config))
					return null;
			}

			let cfg = this._configs[config],
			    extended = match(section, "^@([A-Za-z0-9_-]+)\[(-?[0-9]+)\]$");

			if (extended) {
				let stype = extended[1],
				    sindex = +extended[2];

				let sids = sort(
					filter(keys(cfg), sid => cfg[sid]['.type'] == stype),
					(a, b) => cfg[a]['.index'] - cfg[b]['.index']
				);

				if (sindex < 0)
					sindex = sids.length + sindex;

				return cfg[sids[sindex]];
			}

			return cfg[section];
		},

		get: function(config, section, option) {
			let sobj = this._get_section(config, section);

			if (option && index(option, ".") == 0)
				return null;
			else if (sobj && option)
				return sobj[option];
			else if (sobj)
				return sobj[".type"];
		},

		get_all: function(config, section) {
			return section ? this._get_section(config, section) : this._configs[config];
		},

		foreach: function(config, stype, cb) {
			let rv = false;

			if (exists(this._configs, config)) {
				let cfg = this._configs[config],
				    sids = sort(keys(cfg), (a, b) => cfg[a]['.index'] - cfg[b]['.index']);

				for (let i, sid in sids) {
					if (stype == null || cfg[sid]['.type'] == stype) {
						if (cb({ ...(cfg[sid]) }) === false)
							break;

						rv = true;
					}
				}
			}

			return rv;
		}
	})
};
