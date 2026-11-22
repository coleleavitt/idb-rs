//! `export-sqlite`: write the contents of an IDB/I64 into a SQLite database.

use std::collections::BTreeMap;
use std::io::{BufRead, Seek};
use std::path::Path;
use std::time::Instant;

use anyhow::{anyhow, Result};
use idb_rs::addr_info::{AddressInfo, StrWidth};
use idb_rs::bytes_info::BytesInfo;
use idb_rs::id0::flag::netnode::nn_res::{ARRAY_ALT_TAG, ARRAY_SUP_TAG};
use idb_rs::id0::function::IDBFunctionType;
use idb_rs::id0::{ID0Section, Netdelta, NetnodeIdx};
use idb_rs::id1::{ByteType, ID1Section};
use idb_rs::id2::ID2Section;
use idb_rs::nam::NamSection;
use idb_rs::til::section::TILSection;
use idb_rs::til::TILTypeSizeSolver;
use idb_rs::{Address, IDAKind, IDAVariants, IDBFormat};
use rusqlite::{params, Transaction};

use crate::export_til_sqlite::{
    guarded, insert_til, insert_til_header, open_new_db, TIL_INDEXES,
    TIL_SCHEMA,
};
use crate::tilib::named_decl;
use crate::{get_sections, Args, ExportSqliteArgs, ParseSection};

const SCHEMA: &str = "
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE segments (
    start INTEGER, end INTEGER, name TEXT, class TEXT, perm TEXT,
    bitness INTEGER, type TEXT, align TEXT, comb TEXT, selector INTEGER,
    flags TEXT, orgbase INTEGER, color INTEGER
);
CREATE TABLE segment_strings (idx INTEGER, name TEXT);
CREATE TABLE functions (
    start INTEGER PRIMARY KEY, end INTEGER, name TEXT, dummy_name INTEGER, flags INTEGER,
    flags_text TEXT, frame INTEGER, frsize INTEGER, frregs INTEGER,
    argsize INTEGER, fpd INTEGER, tailqty INTEGER, pntqty INTEGER,
    regvarqty INTEGER, llabelqty INTEGER, color INTEGER, prototype TEXT
);
CREATE TABLE function_chunks (start INTEGER, end INTEGER, owner INTEGER, flags INTEGER);
CREATE TABLE function_regvars (
    func INTEGER, start INTEGER, end INTEGER, register TEXT, name TEXT, comment TEXT
);
CREATE TABLE names (
    ea INTEGER PRIMARY KEY, name TEXT, aflags INTEGER, is_public INTEGER, is_weak INTEGER
);
CREATE TABLE comments (ea INTEGER, kind TEXT, line INTEGER, text TEXT);
CREATE TABLE imports (module TEXT, ea INTEGER, name TEXT, ordinal INTEGER);
CREATE TABLE exports (ea INTEGER, name TEXT, forwarded TEXT, prototype TEXT);
CREATE TABLE heads (ea INTEGER PRIMARY KEY, size INTEGER, flags INTEGER, kind TEXT, data_type TEXT);
CREATE TABLE strings (ea INTEGER PRIMARY KEY, len INTEGER, width INTEGER, layout TEXT, text TEXT);
CREATE TABLE xrefs (frm INTEGER, \"to\" INTEGER, type INTEGER, type_name TEXT, is_code INTEGER, user INTEGER);
CREATE TABLE netnodes (
    key BLOB, value BLOB, node INTEGER, tag TEXT, idx INTEGER, subkey BLOB
);
CREATE TABLE pseudocode (ea INTEGER PRIMARY KEY, name TEXT, text TEXT);
CREATE TABLE export_errors (\"table\" TEXT, count INTEGER, example TEXT);
";

const INDEXES: &str = "
CREATE INDEX segments_start ON segments(start);
CREATE INDEX functions_name ON functions(name);
CREATE INDEX functions_end ON functions(end);
CREATE INDEX function_chunks_owner ON function_chunks(owner);
CREATE INDEX function_regvars_func ON function_regvars(func);
CREATE INDEX names_name ON names(name);
CREATE INDEX comments_ea ON comments(ea);
CREATE INDEX imports_name ON imports(name);
CREATE INDEX imports_ea ON imports(ea);
CREATE INDEX exports_name ON exports(name);
CREATE INDEX exports_ea ON exports(ea);
CREATE INDEX xrefs_frm ON xrefs(frm);
CREATE INDEX xrefs_to ON xrefs(\"to\");
CREATE INDEX netnodes_node ON netnodes(node, tag, idx);
CREATE INDEX netnodes_key ON netnodes(key);
CREATE VIEW types AS SELECT * FROM til_types WHERE til_id = 1;
CREATE VIRTUAL TABLE pseudocode_fts USING fts5(
    name, text, content='pseudocode', content_rowid='ea'
);
INSERT INTO pseudocode_fts(rowid, name, text) SELECT ea, name, text FROM pseudocode;
";

/// Per-table parse error counts, with the first error seen as an example.
#[derive(Default)]
struct Errors(BTreeMap<&'static str, (u64, String)>);

impl Errors {
    fn add(&mut self, table: &'static str, err: impl std::fmt::Display) {
        let entry = self.0.entry(table).or_insert((0, err.to_string()));
        entry.0 += 1;
    }
}

struct Sections<K: IDAKind> {
    id0: ID0Section<K>,
    id1: ID1Section<K>,
    id2: Option<ID2Section<K>>,
    nam: Option<NamSection<K>>,
    til: Option<TILSection>,
}

fn read_sections(
    args: &Args,
) -> Result<IDAVariants<Sections<idb_rs::IDA32>, Sections<idb_rs::IDA64>>> {
    struct Parse;
    impl ParseSection for Parse {
        type Section<K: IDAKind> = Sections<K>;
        fn parse_section<K: IDAKind, F: IDBFormat<K>, I: BufRead + Seek>(
            idb: F,
            mut input: I,
        ) -> Result<Self::Section<K>> {
            let id0 = idb.id0_location().ok_or_else(|| anyhow!("no ID0"))?;
            let id1 = idb.id1_location().ok_or_else(|| anyhow!("no ID1"))?;
            let id2 = idb.id2_location();
            let nam = idb.nam_location();
            let til = idb.til_location();
            Ok(Sections {
                id0: idb.read_id0(&mut input, id0)?,
                id1: idb.read_id1(&mut input, id1)?,
                id2: id2.map(|l| idb.read_id2(&mut input, l)).transpose()?,
                nam: nam.map(|l| idb.read_nam(&mut input, l)).transpose()?,
                til: til.map(|l| idb.read_til(&mut input, l)).transpose()?,
            })
        }
    }
    get_sections::<Parse>(args)
}

pub fn export_sqlite(
    args: &Args,
    export_args: &ExportSqliteArgs,
) -> Result<()> {
    let started = Instant::now();
    let sections = read_sections(args)?;
    eprintln!("parsed sections in {:.1}s", started.elapsed().as_secs_f64());
    let mut conn = open_new_db(&export_args.output)?;
    let tx = conn.transaction()?;
    tx.execute_batch(SCHEMA)?;
    tx.execute_batch(TIL_SCHEMA)?;
    let mut errors = Errors::default();
    let result = match &sections {
        IDAVariants::IDA32(s) => export_kind(&tx, s, &mut errors),
        IDAVariants::IDA64(s) => export_kind(&tx, s, &mut errors),
    };
    result?;
    drop(sections);
    if let Some(dir) = &export_args.pseudocode_dir {
        let step = Instant::now();
        let n = insert_pseudocode(&tx, dir, &mut errors)?;
        eprintln!(
            "pseudocode: {n} rows ({:.1}s)",
            step.elapsed().as_secs_f64()
        );
    }
    {
        let mut stmt = tx.prepare(
            "INSERT INTO export_errors (\"table\", count, example) VALUES (?1, ?2, ?3)",
        )?;
        for (table, (count, example)) in &errors.0 {
            eprintln!("parse errors in {table}: {count} (first: {example})");
            stmt.execute(params![table, *count as i64, example])?;
        }
    }
    let step = Instant::now();
    tx.execute_batch(INDEXES)?;
    tx.execute_batch(TIL_INDEXES)?;
    eprintln!("indexes in {:.1}s", step.elapsed().as_secs_f64());
    tx.commit()?;
    eprintln!("done in {:.1}s", started.elapsed().as_secs_f64());
    Ok(())
}

fn u(value: impl Into<u64>) -> i64 {
    value.into() as i64
}

fn ea<K: IDAKind>(address: Address<K>) -> i64 {
    u(address.into_raw())
}

fn export_kind<K: IDAKind>(
    tx: &Transaction,
    s: &Sections<K>,
    errors: &mut Errors,
) -> Result<()> {
    let id0 = &s.id0;
    let root_idx = id0.root_node()?;
    let root_info = id0.ida_info(root_idx)?;
    let netdelta = root_info.netdelta();

    let mut step = Instant::now();
    let done = |what: &str, step: &mut Instant| {
        eprintln!("{what} ({:.1}s)", step.elapsed().as_secs_f64());
        *step = Instant::now();
    };

    insert_meta(tx, s, errors)?;
    done("meta", &mut step);

    let til_id = insert_til_header(tx, "<local types>", s.til.as_ref(), None)?;
    if let Some(til) = &s.til {
        insert_til(tx, til_id, til)?;
    }
    done("local types", &mut step);
    let mut solver = s.til.as_ref().map(TILTypeSizeSolver::new);

    insert_segments(tx, id0, errors)?;
    insert_functions(tx, s, netdelta, &root_info, solver.as_mut(), errors)?;
    done("segments, functions", &mut step);
    insert_names(tx, s, netdelta, errors)?;
    insert_imports_exports(tx, id0, &root_info, solver.as_mut(), errors)?;
    done("names, imports, exports", &mut step);
    insert_heads(tx, s, netdelta, errors)?;
    done("heads, strings", &mut step);
    insert_netnodes(tx, s, netdelta, errors)?;
    done("netnodes, xrefs, comments", &mut step);
    Ok(())
}

fn insert_meta<K: IDAKind>(
    tx: &Transaction,
    s: &Sections<K>,
    errors: &mut Errors,
) -> Result<()> {
    let id0 = &s.id0;
    let idx = id0.root_node()?;
    let info = id0.ida_info(idx)?;
    let mut rows: Vec<(&str, String)> = vec![
        ("bitness", (K::BYTES * 8).to_string()),
        (
            "processor",
            String::from_utf8_lossy(&info.target.processor).into_owned(),
        ),
        ("idb_version", info.version.to_string()),
        (
            "netdelta",
            format!(
                "{:#x}",
                u(info
                    .netdelta()
                    .ea2node(Address::from_raw(0u8.into()))
                    .into_raw())
            ),
        ),
        ("ida_info", format!("{info:?}")),
    ];
    let mut opt = |key: &'static str, value: Result<Option<String>>| match value
    {
        Ok(Some(v)) => rows.push((key, v)),
        Ok(None) => {}
        Err(err) => errors.add("meta", format!("{key}: {err:#}")),
    };
    opt(
        "input_file",
        Ok(id0.input_file(idx).map(|f| f.as_utf8_lossy().into_owned())),
    );
    opt(
        "input_file_size",
        id0.input_file_size(idx).map(|v| v.map(|v| v.to_string())),
    );
    opt(
        "input_file_crc32",
        id0.input_file_crc32(idx)
            .map(|v| v.map(|v| format!("{v:08x}"))),
    );
    opt(
        "input_file_md5",
        id0.input_file_md5(idx).map(|v| v.map(|v| hex(v))),
    );
    opt(
        "input_file_sha256",
        id0.input_file_sha256(idx).map(|v| v.map(|v| hex(v))),
    );
    opt(
        "image_base",
        id0.image_base(idx)
            .map(|v| v.map(|v| format!("{:#x}", ea(v)))),
    );
    opt(
        "database_creation_version",
        Ok(id0.database_creation_version(idx).map(|v| v.into_owned())),
    );
    opt(
        "database_initial_version",
        id0.database_initial_version(idx)
            .map(|v| v.map(|v| v.to_string())),
    );
    opt(
        "database_creation_time",
        id0.database_creation_time(idx)
            .map(|v| v.map(|v| v.to_string())),
    );
    opt(
        "database_num_opens",
        id0.database_num_opens(idx)
            .map(|v| v.map(|v| v.to_string())),
    );
    opt(
        "database_secs_opens",
        id0.database_secs_opens(idx)
            .map(|v| v.map(|v| v.to_string())),
    );
    opt(
        "c_header_path",
        Ok(id0.c_header_path(idx).map(|v| v.into_owned())),
    );
    opt(
        "c_predefined_macros",
        Ok(id0.c_predefined_macros(idx).map(|v| v.into_owned())),
    );
    let mut stmt =
        tx.prepare("INSERT INTO meta (key, value) VALUES (?1, ?2)")?;
    for (key, value) in rows {
        stmt.execute(params![key, value])?;
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn insert_segments<K: IDAKind>(
    tx: &Transaction,
    id0: &ID0Section<K>,
    errors: &mut Errors,
) -> Result<()> {
    let mut names = BTreeMap::new();
    if let Some(idx) = id0.segment_strings_idx()? {
        let mut stmt = tx.prepare(
            "INSERT INTO segment_strings (idx, name) VALUES (?1, ?2)",
        )?;
        for entry in id0.segment_strings(idx) {
            match entry {
                Ok((name_idx, name)) => {
                    let name = name.as_utf8_lossy().into_owned();
                    stmt.execute(params![u(name_idx.0), name])?;
                    names.insert(u(name_idx.0), name);
                }
                Err(err) => errors.add("segment_strings", format!("{err:#}")),
            }
        }
    }
    let Some(idx) = id0.segments_idx()? else {
        return Ok(());
    };
    let mut stmt = tx.prepare(
        "INSERT INTO segments (start, end, name, class, perm, bitness, type,
            align, comb, selector, flags, orgbase, color)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
    )?;
    for seg in id0.segments(idx) {
        let seg = match seg {
            Ok(seg) => seg,
            Err(err) => {
                errors.add("segments", format!("{err:#}"));
                continue;
            }
        };
        let perm = seg.perm.map(|p| {
            [
                (p.can_read(), 'r'),
                (p.can_write(), 'w'),
                (p.can_execute(), 'x'),
            ]
            .iter()
            .map(|(set, c)| if *set { *c } else { '-' })
            .collect::<String>()
        });
        stmt.execute(params![
            ea(seg.address.start),
            ea(seg.address.end),
            names.get(&u(seg.name.0)),
            names.get(&u(seg.class_id.0)),
            perm,
            format!("{:?}", seg.bitness),
            format!("{:?}", seg.seg_type),
            format!("{:?}", seg.align),
            format!("{:?}", seg.comb),
            u(seg.selector),
            format!("{:?}", seg.flags),
            u(seg.orgbase),
            seg.color,
        ])?;
    }
    Ok(())
}

fn label<K: IDAKind>(
    id0: &ID0Section<K>,
    netdelta: Netdelta<K>,
    address: Address<K>,
) -> Result<Option<String>> {
    let Some(info) = AddressInfo::new_forced(id0, netdelta, address) else {
        return Ok(None);
    };
    Ok(info.label()?.map(|l| l.as_utf8_lossy().into_owned()))
}

fn insert_functions<K: IDAKind>(
    tx: &Transaction,
    s: &Sections<K>,
    netdelta: Netdelta<K>,
    root_info: &idb_rs::id0::RootInfo<K>,
    mut solver: Option<&mut TILTypeSizeSolver<'_>>,
    errors: &mut Errors,
) -> Result<()> {
    let id0 = &s.id0;
    let Some(funcs_idx) = id0.funcs_idx()? else {
        return Ok(());
    };
    let mut funcs = tx.prepare(
        "INSERT OR IGNORE INTO functions (start, end, name, dummy_name, flags,
            flags_text, frame, frsize, frregs, argsize, fpd, tailqty, pntqty,
            regvarqty, llabelqty, color, prototype)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
    )?;
    let mut chunks = tx.prepare(
        "INSERT INTO function_chunks (start, end, owner, flags) VALUES (?1, ?2, ?3, ?4)",
    )?;
    for func in id0.fchunks(funcs_idx) {
        let func = match func {
            Ok(func) => func,
            Err(err) => {
                errors.add("functions", format!("{err:#}"));
                continue;
            }
        };
        let start = func.address.start;
        let data = match &func.extra {
            IDBFunctionType::Tail(tail) => {
                chunks.execute(params![
                    ea(start),
                    ea(func.address.end),
                    ea(tail.owner),
                    u(func.flags.into_raw()),
                ])?;
                continue;
            }
            IDBFunctionType::NonTail(data) => data,
        };
        let name = label(id0, netdelta, start).unwrap_or_else(|err| {
            errors.add("functions.name", format!("{:#x}: {err:#}", ea(start)));
            None
        });
        let prototype =
            AddressInfo::new(id0, &s.id1, s.id2.as_ref(), netdelta, start)
                .map(|info| info.tinfo(root_info))
                .transpose()
                .map(Option::flatten)
                .unwrap_or_else(|err| {
                    errors.add(
                        "functions.prototype",
                        format!("{:#x}: {err:#}", ea(start)),
                    );
                    None
                })
                .and_then(|ty| {
                    let solver = solver.as_deref_mut()?;
                    guarded(|| {
                        named_decl(
                            name.as_deref().map(str::as_bytes),
                            &ty,
                            solver,
                        )
                        .map_err(Into::into)
                    })
                    .map_err(|err| errors.add("functions.prototype", err))
                    .ok()
                });
        let dummy_name = name.is_none();
        let name = name.unwrap_or_else(|| format!("sub_{:X}", ea(start)));
        funcs.execute(params![
            ea(start),
            ea(func.address.end),
            name,
            dummy_name,
            u(func.flags.into_raw()),
            format!("{:?}", func.flags),
            u(data.frame),
            u(data.frsize),
            data.frregs,
            u(data.argsize),
            u(data.fpd),
            data.tailqty,
            data.pntqty,
            data.regvarqty,
            data.llabelqty,
            data.color,
            prototype,
        ])?;
        insert_function_extras(
            tx, id0, funcs_idx, netdelta, &func, data, errors,
        )?;
    }
    Ok(())
}

/// Register variables and function comments of one function.
fn insert_function_extras<K: IDAKind>(
    tx: &Transaction,
    id0: &ID0Section<K>,
    funcs_idx: idb_rs::id0::function::FuncIdx<K>,
    netdelta: Netdelta<K>,
    func: &idb_rs::id0::function::IDBFunction<K>,
    data: &idb_rs::id0::function::IDBFunctionNonTail<K>,
    errors: &mut Errors,
) -> Result<()> {
    let start = func.address.start;
    let mut regvars = tx.prepare_cached(
        "INSERT INTO function_regvars (func, start, end, register, name, comment)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    if data.regvarqty > 0 {
        for reg in id0.function_defined_registers(netdelta, func, data) {
            let reg = match reg {
                Ok(reg) => reg,
                Err(err) => {
                    errors.add("function_regvars", format!("{err:#}"));
                    continue;
                }
            };
            regvars.execute(params![
                ea(start),
                ea(reg.range.start),
                ea(reg.range.end),
                reg.register_name.as_utf8_lossy(),
                reg.variable_name.as_utf8_lossy(),
                reg.cmt.as_utf8_lossy(),
            ])?;
        }
    }
    let mut comments = tx.prepare_cached(
        "INSERT INTO comments (ea, kind, line, text) VALUES (?1, ?2, 0, ?3)",
    )?;
    for (kind, cmt) in [
        ("function", id0.func_cmt(funcs_idx, netdelta, start)),
        (
            "function_repeatable",
            id0.func_repeatable_cmt(funcs_idx, netdelta, start),
        ),
    ] {
        match cmt {
            Ok(Some(text)) => {
                comments.execute(params![
                    ea(start),
                    kind,
                    text.as_utf8_lossy()
                ])?;
            }
            Ok(None) => {}
            Err(err) => errors.add("comments.function", format!("{err:#}")),
        }
    }
    Ok(())
}

// AFL_PUBNAM / AFL_WEAKNAM from nalt.hpp
const AFL_PUBNAM: u64 = 0x4;
const AFL_WEAKNAM: u64 = 0x8;
const NALT_AFLAGS: u8 = 8;

fn insert_names<K: IDAKind>(
    tx: &Transaction,
    s: &Sections<K>,
    netdelta: Netdelta<K>,
    errors: &mut Errors,
) -> Result<()> {
    let Some(nam) = &s.nam else {
        return Ok(());
    };
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO names (ea, name, aflags, is_public, is_weak)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for &address in &nam.names {
        let name = match label(&s.id0, netdelta, address) {
            Ok(name) => name,
            Err(err) => {
                errors.add("names", format!("{:#x}: {err:#}", ea(address)));
                continue;
            }
        };
        let aflags = s
            .id0
            .altval(
                netdelta.ea2node(address),
                NALT_AFLAGS.into(),
                ARRAY_ALT_TAG,
            )
            .unwrap_or_else(|err| {
                errors.add("names.aflags", format!("{err:#}"));
                None
            })
            .map(|v| u(v.into_raw()));
        let bit = |b: u64| aflags.map(|f| (f as u64 & b != 0) as i64);
        stmt.execute(params![
            ea(address),
            name,
            aflags,
            bit(AFL_PUBNAM),
            bit(AFL_WEAKNAM),
        ])?;
    }
    Ok(())
}

fn insert_imports_exports<K: IDAKind>(
    tx: &Transaction,
    id0: &ID0Section<K>,
    root_info: &idb_rs::id0::RootInfo<K>,
    mut solver: Option<&mut TILTypeSizeSolver<'_>>,
    errors: &mut Errors,
) -> Result<()> {
    // `$ imports`: altval i = module netnode, supval i = module name; each
    // module netnode has supval ea = imported name, altval ea = ordinal.
    if let Some(imports) = id0.netnode_idx_by_name("$ imports")? {
        let mut stmt = tx.prepare(
            "INSERT INTO imports (module, ea, name, ordinal) VALUES (?1, ?2, ?3, ?4)",
        )?;
        let modules: Vec<_> = id0
            .sup_range(imports, ARRAY_ALT_TAG)
            .filter_map(|entry| {
                let (i, value) = entry.ok()?;
                let node = K::usize_try_from_le_bytes(value)?;
                (i != !K::Usize::from(0u8)).then_some((i, node))
            })
            .collect();
        for (i, node) in modules {
            let module = id0
                .sup_value(imports, i, ARRAY_SUP_TAG)
                .map(|v| String::from_utf8_lossy(trim_nul(v)).into_owned());
            let node = NetnodeIdx::from_raw(node);
            for entry in id0.sup_range(node, ARRAY_SUP_TAG) {
                let (address, value) = match entry {
                    Ok(entry) => entry,
                    Err(err) => {
                        errors.add("imports", format!("{err:#}"));
                        continue;
                    }
                };
                let ordinal = id0
                    .altval(node, address, ARRAY_ALT_TAG)
                    .ok()
                    .flatten()
                    .map(|v| u(v.into_raw()));
                stmt.execute(params![
                    module,
                    u(address),
                    String::from_utf8_lossy(trim_nul(value)),
                    ordinal,
                ])?;
            }
        }
    }

    let entries = match id0.entry_points(root_info) {
        Ok(entries) => entries,
        Err(err) => {
            errors.add("exports", format!("{err:#}"));
            return Ok(());
        }
    };
    let mut stmt = tx.prepare(
        "INSERT INTO exports (ea, name, forwarded, prototype) VALUES (?1, ?2, ?3, ?4)",
    )?;
    for entry in entries {
        let prototype = entry.entry_type.as_ref().and_then(|ty| {
            let solver = solver.as_deref_mut()?;
            guarded(|| {
                named_decl(Some(entry.name.as_bytes()), ty, solver)
                    .map_err(Into::into)
            })
            .map_err(|err| errors.add("exports.prototype", err))
            .ok()
        });
        stmt.execute(params![
            u(entry.address),
            entry.name,
            entry.forwarded,
            prototype
        ])?;
    }
    Ok(())
}

fn trim_nul(value: &[u8]) -> &[u8] {
    value.strip_suffix(b"\0").unwrap_or(value)
}

fn insert_heads<K: IDAKind>(
    tx: &Transaction,
    s: &Sections<K>,
    netdelta: Netdelta<K>,
    errors: &mut Errors,
) -> Result<()> {
    let bytes = BytesInfo::new(Some(&s.id1), s.id2.as_ref());
    let mut heads = tx.prepare(
        "INSERT OR IGNORE INTO heads (ea, size, flags, kind, data_type)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut strings = tx.prepare(
        "INSERT OR IGNORE INTO strings (ea, len, width, layout, text)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut buf = Vec::new();
    for (address, info, len) in bytes.all_bytes_no_tails() {
        let (kind, data_type) = match info.byte_type() {
            ByteType::Code(_) => ("code", None),
            ByteType::Data(data) => ("data", Some(data.data_type())),
            ByteType::Tail(_) | ByteType::Unknown => continue,
        };
        heads.execute(params![
            ea(address),
            len as i64,
            info.as_raw(),
            kind,
            data_type.map(|t| format!("{t:?}")),
        ])?;
        if data_type != Some(idb_rs::id1::ByteDataType::Strlit) {
            continue;
        }
        let Some(str_type) = AddressInfo::new_forced(&s.id0, netdelta, address)
            .and_then(|info| info.str_type())
        else {
            errors.add("strings", format!("{:#x}: no strtype", ea(address)));
            continue;
        };
        buf.clear();
        let base: u64 = address.into_raw().into();
        for i in 0..len as u64 {
            let Ok(at) = K::Usize::try_from(base + i) else {
                break;
            };
            match bytes
                .byte_by_address(Address::from_raw(at))
                .and_then(|b| b.data())
            {
                Some(byte) => buf.push(byte),
                None => break,
            }
        }
        let (width, text) = decode_string(&buf, str_type.width);
        strings.execute(params![
            ea(address),
            len as i64,
            width,
            format!("{:?}", str_type.layout),
            text,
        ])?;
    }
    Ok(())
}

fn decode_string(bytes: &[u8], width: StrWidth) -> (i64, String) {
    match width {
        StrWidth::Byte => {
            let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
            (1, String::from_utf8_lossy(&bytes[..end]).into_owned())
        }
        StrWidth::Word => {
            let units: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .take_while(|c| *c != 0)
                .collect();
            (2, String::from_utf16_lossy(&units))
        }
        StrWidth::Dword => {
            let text = bytes
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| u32::from_le_bytes(*c))
                .take_while(|c| *c != 0)
                .map(|c| char::from_u32(c).unwrap_or('\u{fffd}'))
                .collect();
            (4, text)
        }
    }
}

// xref types from xref.hpp (cref_t / dref_t) and the XREF_* flag bits
fn xref_type_name(is_code: bool, raw: u8) -> &'static str {
    match (is_code, raw & 0x1f) {
        (true, 16) => "call_far",
        (true, 17) => "call_near",
        (true, 18) => "jump_far",
        (true, 19) => "jump_near",
        (true, 20) => "user_specified",
        (true, 21) => "flow",
        (false, 1) => "offset",
        (false, 2) => "write",
        (false, 3) => "read",
        (false, 4) => "text",
        (false, 5) => "informational",
        (false, 6) => "enum_member",
        _ => "unknown",
    }
}
const XREF_USER: u8 = 0x20;

/// One pass over every ID0 entry: the raw netnode table, plus the xrefs
/// and address comments decoded from their netnode tags.
fn insert_netnodes<K: IDAKind>(
    tx: &Transaction,
    s: &Sections<K>,
    netdelta: Netdelta<K>,
    errors: &mut Errors,
) -> Result<()> {
    let bytes = BytesInfo::new(Some(&s.id1), s.id2.as_ref());
    let mut raw = tx.prepare(
        "INSERT INTO netnodes (key, value, node, tag, idx, subkey)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    let mut xrefs = tx.prepare(
        "INSERT INTO xrefs (frm, \"to\", type, type_name, is_code, user)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    let mut comments = tx.prepare(
        "INSERT INTO comments (ea, kind, line, text) VALUES (?1, ?2, ?3, ?4)",
    )?;
    let word = usize::from(K::BYTES);
    for entry in s.id0.all_entries() {
        let key = &entry.key[..];
        let is_netnode = key.first() == Some(&b'.') && key.len() > word;
        if !is_netnode {
            raw.execute(params![
                key,
                &entry.value[..],
                None::<i64>,
                None::<String>,
                None::<i64>,
                None::<Vec<u8>>
            ])?;
            continue;
        }
        let Some(node) = K::usize_try_from_be_bytes(&key[1..1 + word]) else {
            errors.add("netnodes", "bad netnode key");
            continue;
        };
        let tag = key.get(1 + word).copied();
        let rest = key.get(2 + word..).unwrap_or(&[]);
        let idx = (rest.len() == word)
            .then(|| K::usize_try_from_be_bytes(rest))
            .flatten();
        let subkey = (!rest.is_empty() && idx.is_none()).then_some(rest);
        raw.execute(params![
            key,
            &entry.value[..],
            u(node),
            tag.map(|t| (t as char).to_string()),
            idx.map(u),
            subkey,
        ])?;

        let (Some(tag), Some(idx)) = (tag, idx) else {
            continue;
        };
        match tag {
            b'x' | b'd' => {
                let is_code = tag == b'x';
                let Some(&kind) = entry.value.first() else {
                    errors.add("xrefs", "empty xref value");
                    continue;
                };
                let from = netdelta.node2ea(NetnodeIdx::from_raw(node));
                let to = netdelta.node2ea(NetnodeIdx::from_raw(idx));
                // the same tags also appear on non-address netnodes
                if bytes.byte_by_address(from).is_none() {
                    continue;
                }
                xrefs.execute(params![
                    ea(from),
                    ea(to),
                    kind,
                    xref_type_name(is_code, kind),
                    is_code,
                    kind & XREF_USER != 0,
                ])?;
            }
            ARRAY_SUP_TAG => {
                let idx: u64 = idx.into();
                let (kind, line) = match idx {
                    0 => ("regular", 0),
                    1 => ("repeatable", 0),
                    1000..2000 => ("anterior", idx - 1000),
                    2000..3000 => ("posterior", idx - 2000),
                    _ => continue,
                };
                let address = netdelta.node2ea(NetnodeIdx::from_raw(node));
                // IDA hides comments left on bytes that became item tails
                let is_head = bytes
                    .byte_by_address(address)
                    .is_some_and(|b| !b.byte_type().is_tail());
                if !is_head {
                    continue;
                }
                comments.execute(params![
                    ea(address),
                    kind,
                    line as i64,
                    String::from_utf8_lossy(trim_nul(&entry.value)),
                ])?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Load a Hex-Rays dump directory: one `<name>.c` file per function whose
/// first line is `// <name> @ 0x<ea>`.
fn insert_pseudocode(
    tx: &Transaction,
    dir: &Path,
    errors: &mut Errors,
) -> Result<u64> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO pseudocode (ea, name, text) VALUES (?1, ?2, ?3)",
    )?;
    let mut count = 0;
    let mut paths: Vec<_> = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    paths.sort();
    for path in paths {
        if path.extension().is_none_or(|e| e != "c") {
            continue;
        }
        let text = match std::fs::read(&path) {
            Ok(text) => String::from_utf8_lossy(&text).into_owned(),
            Err(err) => {
                errors.add("pseudocode", format!("{}: {err}", path.display()));
                continue;
            }
        };
        let header = text.lines().next().unwrap_or("");
        let parsed = header
            .strip_prefix("// ")
            .and_then(|h| h.rsplit_once(" @ 0x"))
            .and_then(|(name, ea)| {
                Some((name, u64::from_str_radix(ea.trim(), 16).ok()?))
            });
        let Some((name, address)) = parsed else {
            errors.add(
                "pseudocode",
                format!("{}: no `// name @ 0xEA` header", path.display()),
            );
            continue;
        };
        if stmt.execute(params![address as i64, name, text])? == 0 {
            errors.add(
                "pseudocode",
                format!("{}: duplicate ea {address:#x}", path.display()),
            );
            continue;
        }
        count += 1;
    }
    Ok(count)
}
