(function () {
    'use strict';
    println(document.getElementById('manuf_list'));
    var manuf_file = document.getElementById('manuf_list');
    var manuf_entries;

    var parse_mac_address = function (val) {
        var m;
        val = val.toLowerCase();
        // Accept any sequence of two hexadecimal blocks with an optional
        // separator, with a minimum length of 3 and a maximum of 8.
        // Returns a concatenation of these blocks without separators.
        // Examples:
        // xx:yy:zz or xx-yy-zz, or xx.yy.zz -> xxyyzz
        // aabb.ccdd.eeff -> aabbccddeeff
        if ((m = /^[0-9a-f]{2}(?:[:.-]?[0-9a-f]{2}){2,7}$/.exec(val))) {
            return m[0].replace(/[:.-]/g, '');
        }
        return null;
    };

    var formatEntry = function (prefix, name) {
        var prefixLength = prefix.length;
        var str = prefix.replace(/../g, '$&:').replace(/:$/, '').toUpperCase();
        if (prefixLength == 9) {
            // 36 bits, xx-xx-xx-xx-x0-00
            str += '0:00/36';
        } else if (prefixLength == 7) {
            // 28 bits, xx-xx-xx-x0-00-00
            str += '0:00:00/28';
        }
        str += ' ' + name;
        return str;
    };

    var do_oui_lookup = function () {
        var queries = document.getElementById('mac').value.split('\n');
        var prefixes = [],
            names = [],
            name_regex;
        queries.forEach(function (query) {
            query = query.replace(/^\s+|\s+$/g, '');
            var prefix = parse_mac_address(query);
            if (prefix) {
                prefixes.push(prefix);
            } else if (query) {
                // None of the potentially valid patterns caught by
                // parse_mac_address currently match any manufacturer name, so
                // as optimization we can skip trying to match those names here.
                names.push(query);
            }
        });
        if (names.length) {
            name_regex = new RegExp(names.map(function (name) {
                // Escape https://tc39.es/ecma262/#prod-SyntaxCharacter
                name = name.replace(/[\^$\\.*+?()\[\]{}|]/g, '\\$&');
                return '(?:' + name + ')';
            }).join('|'), 'i');
        }

        // Find entries with either a common prefix match or a name match.
        var results = manuf_entries.filter(function (entry) {
            return prefixes.some(function (prefix) {
                    return prefix.substring(0, entry.prefix.length) === entry.prefix.substring(
                        0, prefix.length);
                }) ||
                (name_regex && name_regex.test(entry.name));
        }).map(function (entry) {
            return formatEntry(entry.prefix, entry.name);
        });
        document.getElementById('resultado').textContent = results.join('\n') || 'Sin coincidencias';
    };

    var load_manufdata = function (obj) {
        // Expect a map from prefix to a name. The prefix is a string with
        // lower-case hexadecimal characters representing an address prefix.
        // Its length is either 6, 7 or 9 (for 24, 28 or 36 bits).
        var mapping = obj.data;
        var prefixes = Object.keys(mapping);
        prefixes.sort();
        manuf_entries = prefixes.map(function (prefix) {
            return {
                prefix: prefix,
                name: mapping[prefix]
            };
        });

        var button = document.getElementById('oui-lookup-button');
        button.onclick = do_oui_lookup;
        button.textContent = 'Escanear';
        button.disabled = false;
        console.log('Loaded ' + Object.keys(obj.data).length + ' entries');
        console.log('Created at', obj.created_at);
    };

    var x = new XMLHttpRequest();
    x.onload = function () {
        if (x.status != 200) {
            return;
        }
        load_manufdata(JSON.parse(x.responseText));
    };
    x.open('GET', manuf_file, true);
    x.send(null);
}());
