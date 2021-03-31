{%
	let mocklib = global.mocklib,
	    fs = mocklib.require("fs");

	return {
		readlink: function(path) {
			mocklib.trace_call("fs", "readlink", { path });

			return path + "-link";
		},

		stat: function(path) {
			let file = sprintf("fs/stat~%s.json", replace(path, /[^A-Za-z0-9_-]+/g, '_')),
			    mock = mocklib.read_json_file(file);

			if (!mock || mock != mock) {
				mocklib.I("No stat result fixture defined for fs.stat() call on %s.", path);
				mocklib.I("Provide a mock result through the following JSON file:\n%s\n", file);

				if (match(path, /\/$/))
					mock = { type: "directory" };
				else
					mock = { type: "file" };
			}

			mocklib.trace_call("fs", "stat", { path });

			return mock;
		},

		unlink: function(path) {
			printf("fs.unlink() path <%s>\n", path);

			return true;
		},

		popen: (cmdline, mode) => {
			let read = (!mode || index(mode, "r") != -1),
			    path = sprintf("fs/popen~%s.txt", replace(cmdline, /[^A-Za-z0-9_-]+/g, '_')),
			    mock = mocklib.read_data_file(path);

			if (read && !mock) {
				mocklib.I("No stdout fixture defined for fs.popen() command %s.", cmdline);
				mocklib.I("Provide a mock output through the following text file:\n%s\n", path);

				return null;
			}

			printf("fs.popen() cmdline <%s> mode <%s>\n", cmdline, mode);

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
			    path = sprintf("fs/open~%s.txt", replace(fpath, /[^A-Za-z0-9_-]+/g, '_')),
			    mock = read ? mocklib.read_data_file(path) : null;

			if (read && !mock) {
				mocklib.I("No stdout fixture defined for fs.open() path %s.", fpath);
				mocklib.I("Provide a mock output through the following text file:\n%s\n", path);

				return null;
			}

			mocklib.trace_call("fs", "open", { path: fpath, mode });

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
	};
