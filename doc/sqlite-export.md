# SQLite export

`idb-tools` can write an IDB/I64 database, or a set of TIL type libraries,
into a SQLite file so it can be queried with SQL.

```sh
idb-tools -i libida.so.i64 export-sqlite libida.sqlite --pseudocode-dir out/all
idb-tools -i unused export-til-sqlite tils.sqlite ~/.local/share/ida/9.5/til
```

`export-sqlite` replaces the output file and writes it in one transaction.
Indexes and full-text indexes are built after the bulk insert. An entry that
fails to parse is counted in `export_errors` and skipped; the export goes on.

`--pseudocode-dir` loads a directory of Hex-Rays output, one `<name>.c` file
per function whose first line is `// <name> @ 0x<ea>`.

`export-til-sqlite` loads every `*.til` under the given files or directories
(the `-i` argument is ignored). A file that fails to parse gets a `tils` row
with `error` set.

Addresses are stored as SQLite integers (a 64-bit address above
`0x7fffffffffffffff`, such as `BADADDR`, reads back negative). Use
`printf('0x%X', ea)` to print them in hex.

## Schema: `export-sqlite`

| Table | Contents |
|---|---|
| `meta(key, value)` | root info: input file, size, md5, sha256, crc32, processor, IDA version, image base, creation time, `ida_info` (debug dump of the whole root info) |
| `segments(start, end, name, class, perm, bitness, type, align, comb, selector, flags, orgbase, color)` | `$ segs` |
| `segment_strings(idx, name)` | `$ segstrings` |
| `functions(start, end, name, dummy_name, flags, flags_text, frame, frsize, frregs, argsize, fpd, tailqty, pntqty, regvarqty, llabelqty, color, prototype)` | function entry chunks from `$ funcs`; `name` is `sub_<EA>` when `dummy_name = 1`; `prototype` is the function's type rendered as C |
| `function_chunks(start, end, owner, flags)` | function tail chunks |
| `function_regvars(func, start, end, register, name, comment)` | register variables |
| `names(ea, name, aflags, is_public, is_weak)` | every name in the NAM section; `aflags` is the `NALT_AFLAGS` altval |
| `comments(ea, kind, line, text)` | `kind` is `regular`, `repeatable`, `anterior`, `posterior` (`line` = line number), `function` or `function_repeatable` |
| `imports(module, ea, name, ordinal)` | `$ imports` |
| `exports(ea, name, forwarded, prototype)` | `$ entry points` |
| `heads(ea, size, flags, kind, data_type)` | every code and data item; `flags` is the raw ID1/ID2 flags word |
| `strings(ea, len, width, layout, text)` | string literals, decoded from the item bytes |
| `xrefs(frm, "to", type, type_name, is_code, user)` | code (`x`) and data (`d`) xrefs from ID0; ordinary flow is not stored by IDA, use `heads` for it |
| `netnodes(key, value, node, tag, idx, subkey)` | every raw ID0 entry; for netnode keys `node`, `tag`, and either `idx` (numeric subkey) or `subkey` (hash key) are decoded |
| `pseudocode(ea, name, text)`, `pseudocode_fts` | Hex-Rays output and an FTS5 index over it |
| `tils`, `til_types`, ... | the database's local types, in the TIL tables below (`til_id = 1`) |
| `types` | view: `til_types` of the local types |
| `export_errors(table, count, example)` | parse errors per table |

## Schema: TIL tables (`export-til-sqlite`, and local types in `export-sqlite`)

| Table | Contents |
|---|---|
| `tils(id, file, description, format, compiler, cc, flags, dependencies, type_count, symbol_count, macro_count, decl_errors, error)` | one row per TIL |
| `til_types(til_id, ordinal, name, kind, size, decl)` | `kind`: `struct`, `union`, `enum`, `typedef`, `func`, `pointer`, `array`, `basic`, `bitfield`; `decl` as `print-tilib` prints it |
| `til_members(til_id, type_name, idx, name, decl, offset, bit_offset, size, comment)` | struct/union members; `size` is bits for a bitfield |
| `til_enum_values(til_id, enum_name, name, value, group_name, comment)` | enum constants |
| `til_symbols(til_id, value, name, sclass, decl)` | symbols: function prototypes and globals |
| `til_macros(til_id, name, param_count, value)` | macros |
| `til_types_fts`, `til_symbols_fts` | FTS5 over `name` and `decl` of `til_types` and `til_symbols` (rowid = the row's rowid) |

## Example queries

```sql
-- largest functions
SELECT printf('0x%X', start), name, end - start AS size
FROM functions ORDER BY size DESC LIMIT 10;

-- functions whose pseudocode mentions a name
SELECT printf('0x%X', p.ea), p.name
FROM pseudocode_fts f JOIN pseudocode p ON p.ea = f.rowid
WHERE pseudocode_fts MATCH 'get_func_name';

-- callers of a function, from xrefs
SELECT printf('0x%X', f.start), f.name, count(*)
FROM xrefs x
JOIN functions t ON t.start = x."to"
JOIN functions f ON x.frm >= f.start AND x.frm < f.end
WHERE t.name = 'get_func_name' AND x.type_name LIKE 'call%'
GROUP BY f.start;

-- most called functions
SELECT t.name, count(*) AS n FROM xrefs x
JOIN functions t ON t.start = x."to"
WHERE x.type_name LIKE 'call%' GROUP BY t.start ORDER BY n DESC LIMIT 10;

-- names by prefix
SELECT printf('0x%X', ea), name FROM names WHERE name LIKE 'get_func%' ORDER BY name;

-- most referenced strings
SELECT printf('0x%X', s.ea), s.text, count(*) FROM strings s
JOIN xrefs x ON x."to" = s.ea GROUP BY s.ea ORDER BY 3 DESC LIMIT 10;

-- exported functions with their prototype
SELECT printf('0x%X', ea), prototype FROM exports WHERE name LIKE 'get_func%';

-- segments
SELECT name, printf('0x%X', start), printf('0x%X', end), perm, type FROM segments;

-- local types by name
SELECT ordinal, kind, size, decl FROM types WHERE name LIKE 'Elf64%';

-- anything idb-rs does not decode: raw netnode entries of an address
SELECT tag, idx, hex(subkey), hex(value) FROM netnodes WHERE node = 0x2392FD1;

-- (TIL db) which type library declares a function, and its prototype
SELECT t.file, s.decl FROM til_symbols s JOIN tils t ON t.id = s.til_id
WHERE s.name = 'CreateFileW';

-- (TIL db) structs with a member of a given name
SELECT t.file, m.type_name, m.offset, m.decl FROM til_members m
JOIN tils t ON t.id = m.til_id WHERE m.name = 'cbSize' LIMIT 20;

-- (TIL db) enum constant lookup by name or by value
SELECT enum_name, name, printf('0x%X', value) FROM til_enum_values
WHERE name = 'ERROR_ACCESS_DENIED' OR (enum_name LIKE 'MACRO_ERROR%' AND value = 5);

-- (TIL db) full-text search over declarations
SELECT t.file, s.name, s.decl FROM til_symbols_fts f
JOIN til_symbols s ON s.rowid = f.rowid JOIN tils t ON t.id = s.til_id
WHERE til_symbols_fts MATCH 'decl:HANDLE AND decl:LPCWSTR' LIMIT 20;
```
