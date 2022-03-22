let mocklib = global.mocklib;

return {
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
					let path = sprintf("ubus/%s.json", join("~", signature)),
					    mock = mocklib.read_json_file(path);

					if (mock != mock) {
						self._error = "Invalid argument";

						return null;
					}
					else if (mock) {
						mocklib.trace_call("ctx", "call", { object, method, args });

						return mock;
					}

					push(candidates, path);
					pop(signature);
				}

				mocklib.I("No response fixture defined for ubus call %s/%s with arguments %s.", object, method, args);
				mocklib.I("Provide a mock response through one of the following JSON files:\n%s\n", join("\n", candidates));

				self._error = "Method not found";

				return null;
			},

			disconnect: () => null,

			error: () => self.error()
		};
	},

	error: function() {
		let e = this._error;
		delete this._error;

		return e;
	}
};
