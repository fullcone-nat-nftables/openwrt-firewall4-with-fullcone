{%
	let _fs = require("fs");

	let _log = (level, fmt, ...args) => {
		let color, prefix;

		switch (level) {
		case 'info':
			color = 34;
			prefix = '!';
			break;

		case 'warn':
			color = 33;
			prefix = 'W';
			break;

		case 'error':
			color = 31;
			prefix = 'E';
			break;

		default:
			color = 0;
			prefix = 'I';
		}

		let f = sprintf("\u001b[%d;1m[%s] %s\u001b[0m", color, prefix, fmt);
		warn(replace(sprintf(f, ...args), "\n", "\n    "), "\n");
	};

	let I = (...args) => _log('info', ...args);
	let N = (...args) => _log('notice', ...args);
	let W = (...args) => _log('warn', ...args);
	let E = (...args) => _log('error', ...args);

	let read_json_file = (path) => {
		let fd = _fs.open(path, "r");
		if (fd) {
			let data = fd.read("all");
			fd.close();

			try {
				return json(data);
			}
			catch (e) {
				E("Unable to parse JSON data in %s: %s", path, e);

				return NaN;
			}
		}

		return null;
	};

	let format_json = (data) => {
		let rv;

		let format_value = (value) => {
			switch (type(value)) {
			case "object":
				return sprintf("{ /* %d keys */ }", length(value));

			case "array":
				return sprintf("[ /* %d items */ ]", length(value));

			case "string":
				if (length(value) > 64)
					value = substr(value, 0, 64) + "...";

				/* fall through */
				return sprintf("%J", value);

			default:
				return sprintf("%J", value);
			}
		};

		switch (type(data)) {
		case "object":
			rv = "{";

			let k = sort(keys(data));

			for (let i, n in k)
				rv += sprintf("%s %J: %s", i ? "," : "", n, format_value(data[n]));

			rv += " }";
			break;

		case "array":
			rv = "[";

			for (let i, v in data)
				rv += (i ? "," : "") + " " + format_value(v);

			rv += " ]";
			break;

		default:
			rv = format_value(data);
		}

		return rv;
	};

	let trace_call = (ns, func, args) => {
		let msg = "[call] " +
			(ns ? ns + "." : "") +
			func;

		for (let k, v in args) {
			msg += ' ' + k + ' <';

			switch (type(v)) {
			case "array":
			case "object":
				msg += format_json(v);
				break;

			default:
				msg += v;
			}

			msg += '>';
		}

		switch (TRACE_CALLS) {
		case '1':
		case 'stdout':
			print(msg + "\n");
			break;

		case 'stderr':
			warn(msg + "\n");
			break;
		}
	};


	/* Setup mock environment */
	let mocks = {

		/* Mock ubus module */
		ubus: {
			connect: function() {
				let self = this;

				return {
					call: (object, method, args) => {
						let signature = [ object + "~" + method ];

						if (type(args) == "object") {
							for (let i, k in sort(keys(args))) {
								switch (type(args[k])) {
								case "string":
								case "double":
								case "bool":
								case "int":
									push(signature, k + "-" + replace(args[k], /[^A-Za-z0-9_-]+/g, "_"));
									break;

								default:
									push(signature, type(args[k]));
								}
							}
						}

						let candidates = [];

						for (let i = length(signature); i > 0; i--) {
							let path = sprintf("./tests/mocks/ubus/%s.json", join("~", signature)),
							    mock = read_json_file(path);

							if (mock != mock) {
								self._error = "Invalid argument";

								return null;
							}
							else if (mock) {
								trace_call("ctx", "call", { object, method, args });

								return mock;
							}

							push(candidates, path);
							pop(signature);
						}

						I("No response fixture defined for ubus call %s/%s with arguments %s.", object, method, args);
						I("Provide a mock response through one of the following JSON files:\n%s\n", join("\n", candidates));

						self._error = "Method not found";

						return null;
					},

					disconnect: () => null,

					error: () => self.error()
				};
			},

			error: function() {
				let e = this._error;
				delete(this._error);

				return e;
			}
		},


		/* Mock uci module */
		uci: {
			cursor: () => ({
				_configs: {},

				load: function(file) {
					let basename = replace(file, /^.+\//, ''),
					    path = sprintf("./tests/mocks/uci/%s.json", basename),
					    mock = read_json_file(path);

					if (!mock || mock != mock) {
						I("No configuration fixture defined for uci package %s.", file);
						I("Provide a mock configuration through the following JSON file:\n%s\n", path);

						return null;
					}

					this._configs[basename] = mock;
				},

				_get_section: function(config, section) {
					if (!exists(this._configs, config)) {
						this.load(config);

						if (!exists(this._configs, config))
							return null;
					}

					let extended = match(section, "^@([A-Za-z0-9_-]+)\[(-?[0-9]+)\]$");

					if (extended) {
						let stype = extended[1],
						    sindex = +extended[2],
						    sections = [];

						for (let sid, sobj in this._configs[config])
							if (sobj[".type"] == stype)
								push(sections, sobj);

						sort(sections, (a, b) => (a[".index"] || 999) - (b[".index"] || 999));

						if (sindex < 0)
							sindex = sections.length + sindex;

						return sections[sindex];
					}

					return this._configs[config][section];
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
						let i = 0;

						for (let sid, sobj in this._configs[config]) {
							i++;

							if (stype == null || sobj[".type"] == stype) {
								cb({ ".index": i - 1, ".type": stype, ".name": sid, ...sobj });
								rv = true;
							}
						}
					}

					return rv;
				}
			})
		},


		/* Mock fs module */
		fs: {
			readlink: function(path) {
				trace_call("fs", "readlink", { path });

				return path + "-link";
			},

			stat: function(path) {
				let file = sprintf("./tests/mocks/fs/stat~%s.json", replace(path, /[^A-Za-z0-9_-]+/g, '_')),
				    mock = read_json_file(file);

				if (!mock || mock != mock) {
					I("No stat result fixture defined for fs.stat() call on %s.", path);
					I("Provide a mock result through the following JSON file:\n%s\n", file);

					if (match(path, /\/$/))
						mock = { type: "directory" };
					else
						mock = { type: "file" };
				}

				trace_call("fs", "stat", { path });

				return mock;
			},

			unlink: function(path) {
				trace_call("fs", "unlink", { path });

				return true;
			},

			popen: (cmdline, mode) => {
				let read = (!mode || index(mode, "r") != -1),
				    path = sprintf("./tests/mocks/fs/popen~%s.txt", replace(cmdline, /[^A-Za-z0-9_-]+/g, '_')),
				    fd = read ? _fs.open(path, "r") : null,
				    mock = null;

				if (fd) {
				    mock = fd.read("all");
				    fd.close();
				}

				if (read && !mock) {
					I("No stdout fixture defined for fs.popen() command %s.", cmdline);
					I("Provide a mock output through the following text file:\n%s\n", path);

					return null;
				}

				trace_call("fs", "popen", { cmdline, mode });

				return {
					read: function(amount) {
						let rv;

						switch (amount) {
						case "all":
							rv = mock;
							mock = "";
							break;

						case "line":
							let i = index(mock, "\n");
							i = (i > -1) ? i + 1 : mock.length;
							rv = substr(mock, 0, i);
							mock = substr(mock, i);
							break;

						default:
							let n = +amount;
							n = (n > 0) ? n : 0;
							rv = substr(mock, 0, n);
							mock = substr(mock, n);
							break;
						}

						return rv;
					},

					write: function() {},
					close: function() {},

					error: function() {
						return null;
					}
				};
			},

			open: (fpath, mode) => {
				let read = (!mode || index(mode, "r") != -1 || index(mode, "+") != -1),
				    path = sprintf("./tests/mocks/fs/open~%s.txt", replace(fpath, /[^A-Za-z0-9_-]+/g, '_')),
				    fd = read ? _fs.open(path, "r") : null,
				    mock = null;

				if (fd) {
				    mock = fd.read("all");
				    fd.close();
				}

				if (read && !mock) {
					I("No stdout fixture defined for fs.open() path %s.", fpath);
					I("Provide a mock output through the following text file:\n%s\n", path);

					return null;
				}

				trace_call("fs", "open", { path: fpath, mode });

				return {
					read: function(amount) {
						let rv;

						switch (amount) {
						case "all":
							rv = mock;
							mock = "";
							break;

						case "line":
							let i = index(mock, "\n");
							i = (i > -1) ? i + 1 : mock.length;
							rv = substr(mock, 0, i);
							mock = substr(mock, i);
							break;

						default:
							let n = +amount;
							n = (n > 0) ? n : 0;
							rv = substr(mock, 0, n);
							mock = substr(mock, n);
							break;
						}

						return rv;
					},

					write: function() {},
					close: function() {},

					error: function() {
						return null;
					}
				};
			},

			error: () => "Unspecified error"
		},


		/* Mock stdlib functions */

		system: function(argv, timeout) {
			trace_call(null, "system", { command: argv, timeout });

			return 0;
		},

		time: function() {
			printf("time()\n");

			return 1615382640;
		},

		print: function(...args) {
			if (length(args) == 1 && type(args[0]) in ["array", "object"])
				printf("%s\n", format_json(args[0]));
			else
				global.print(...args);
		}
	};


	/* Execute test file */

	if (!TESTFILE)
		E("The TESTFILE variable is not defined.");

	include(TESTFILE, mocks);
