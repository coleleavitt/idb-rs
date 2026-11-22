//! SQLite export of TIL sections: type libraries (`.til` files) and the local
//! types of an IDB share these tables.

use std::fs::File;
use std::io::BufReader;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use idb_rs::til::r#enum::{Enum, EnumMember, EnumMembers};
use idb_rs::til::section::TILSection;
use idb_rs::til::udt::UDT;
use idb_rs::til::{SClass, TILMacroValue, TILTypeSizeSolver, TypeVariant};
use rusqlite::{params, Connection, Transaction};

use crate::tilib::{named_decl, symbol_decl, type_decl, udt_layout};
use crate::ExportTilSqliteArgs;

pub const TIL_SCHEMA: &str = "
CREATE TABLE tils (
    id INTEGER PRIMARY KEY,
    file TEXT NOT NULL,
    description TEXT,
    format INTEGER,
    compiler TEXT,
    cc TEXT,
    flags INTEGER,
    dependencies TEXT,
    type_count INTEGER,
    symbol_count INTEGER,
    macro_count INTEGER,
    decl_errors INTEGER NOT NULL DEFAULT 0,
    error TEXT
);
CREATE TABLE til_types (
    til_id INTEGER NOT NULL,
    ordinal INTEGER,
    name TEXT,
    kind TEXT,
    size INTEGER,
    decl TEXT
);
CREATE TABLE til_members (
    til_id INTEGER NOT NULL,
    type_name TEXT,
    idx INTEGER,
    name TEXT,
    decl TEXT,
    offset INTEGER,
    bit_offset INTEGER,
    size INTEGER,
    comment TEXT
);
CREATE TABLE til_enum_values (
    til_id INTEGER NOT NULL,
    enum_name TEXT,
    name TEXT,
    value INTEGER,
    group_name TEXT,
    comment TEXT
);
CREATE TABLE til_symbols (
    til_id INTEGER NOT NULL,
    value INTEGER,
    name TEXT,
    sclass TEXT,
    decl TEXT
);
CREATE TABLE til_macros (
    til_id INTEGER NOT NULL,
    name TEXT,
    param_count INTEGER,
    value TEXT
);
";

pub const TIL_INDEXES: &str = "
CREATE INDEX til_types_name ON til_types(name);
CREATE INDEX til_types_til ON til_types(til_id, ordinal);
CREATE INDEX til_members_type ON til_members(type_name);
CREATE INDEX til_members_name ON til_members(name);
CREATE INDEX til_enum_values_name ON til_enum_values(name);
CREATE INDEX til_enum_values_value ON til_enum_values(value);
CREATE INDEX til_symbols_name ON til_symbols(name);
CREATE INDEX til_macros_name ON til_macros(name);
CREATE VIRTUAL TABLE til_types_fts USING fts5(
    name, decl, content='til_types'
);
INSERT INTO til_types_fts(rowid, name, decl)
    SELECT rowid, name, decl FROM til_types;
CREATE VIRTUAL TABLE til_symbols_fts USING fts5(
    name, decl, content='til_symbols'
);
INSERT INTO til_symbols_fts(rowid, name, decl)
    SELECT rowid, name, decl FROM til_symbols;
";

#[derive(Default, Debug)]
pub struct TilCounts {
    pub types: u64,
    pub symbols: u64,
    pub members: u64,
    pub enum_values: u64,
    pub macros: u64,
    pub decl_errors: u64,
}

fn kind_name(variant: &TypeVariant) -> &'static str {
    match variant {
        TypeVariant::Basic(_) => "basic",
        TypeVariant::Pointer(_) => "pointer",
        TypeVariant::Function(_) => "func",
        TypeVariant::Array(_) => "array",
        TypeVariant::Typeref(_) => "typedef",
        TypeVariant::Struct(_) => "struct",
        TypeVariant::Union(_) => "union",
        TypeVariant::Enum(_) => "enum",
        TypeVariant::Bitfield(_) => "bitfield",
    }
}

fn sclass_name(sclass: Option<SClass>) -> Option<String> {
    sclass.map(|s| match s {
        SClass::Other(x) => format!("other({x})"),
        s => format!("{s:?}").to_lowercase(),
    })
}

/// Run a renderer that may panic on unusual type data, turning a panic
/// into an error so the caller can count it and continue.
pub fn guarded<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    catch_unwind(AssertUnwindSafe(f))
        .unwrap_or_else(|_| Err(anyhow!("renderer panicked")))
}

pub fn insert_til_header(
    tx: &Transaction,
    file: &str,
    til: Option<&TILSection>,
    error: Option<&str>,
) -> Result<i64> {
    let header = til.map(|t| &t.header);
    tx.execute(
        "INSERT INTO tils (file, description, format, compiler, cc, flags,
            dependencies, type_count, symbol_count, macro_count, error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            file,
            header.map(|h| h.description.as_utf8_lossy().into_owned()),
            header.map(|h| h.format),
            header.map(|h| format!("{:?}", h.compiler_id)),
            header.and_then(|h| h.cc.map(|cc| format!("{cc:?}"))),
            header.map(|h| h.flags.as_raw()),
            header.map(|h| {
                h.dependencies
                    .iter()
                    .map(|d| d.as_utf8_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(",")
            }),
            til.map(|t| t.types.len() as i64),
            til.map(|t| t.symbols.len() as i64),
            til.map(|t| t.macros.as_ref().map_or(0, |m| m.len()) as i64),
            error,
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

pub fn insert_til(
    tx: &Transaction,
    til_id: i64,
    til: &TILSection,
) -> Result<TilCounts> {
    let mut counts = TilCounts::default();
    let mut solver = TILTypeSizeSolver::new(til);
    let mut types = tx.prepare(
        "INSERT INTO til_types (til_id, ordinal, name, kind, size, decl)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for (idx, ty) in til.types.iter().enumerate() {
        let name = ty.name.as_utf8_lossy();
        let decl = guarded(|| {
            type_decl(ty.name.as_bytes(), idx, &ty.tinfo, &mut solver)
                .map_err(Into::into)
        });
        if decl.is_err() {
            counts.decl_errors += 1;
        }
        let size = guarded(|| Ok(solver.type_size_bytes(Some(idx), &ty.tinfo)))
            .ok()
            .flatten();
        types.execute(params![
            til_id,
            ty.ordinal as i64,
            name,
            kind_name(&ty.tinfo.type_variant),
            size.map(|s| s as i64),
            decl.ok(),
        ])?;
        counts.types += 1;

        match &ty.tinfo.type_variant {
            TypeVariant::Struct(udt) => insert_udt_members(
                tx,
                til_id,
                &name,
                udt,
                false,
                &mut solver,
                &mut counts,
            )?,
            TypeVariant::Union(udt) => insert_udt_members(
                tx,
                til_id,
                &name,
                udt,
                true,
                &mut solver,
                &mut counts,
            )?,
            TypeVariant::Enum(en) => {
                insert_enum_values(tx, til_id, &name, en, &mut counts)?
            }
            _ => {}
        }
    }
    insert_symbols(tx, til_id, til, &mut solver, &mut counts)?;
    insert_macros(tx, til_id, til, &mut counts)?;
    tx.execute(
        "UPDATE tils SET decl_errors = ?1 WHERE id = ?2",
        params![counts.decl_errors as i64, til_id],
    )?;
    Ok(counts)
}

fn insert_udt_members(
    tx: &Transaction,
    til_id: i64,
    type_name: &str,
    udt: &UDT,
    is_union: bool,
    solver: &mut TILTypeSizeSolver<'_>,
    counts: &mut TilCounts,
) -> Result<()> {
    let mut stmt = tx.prepare_cached(
        "INSERT INTO til_members (til_id, type_name, idx, name, decl,
            offset, bit_offset, size, comment)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )?;
    let layout =
        guarded(|| Ok(udt_layout(udt, is_union, solver))).unwrap_or_default();
    for (i, member) in udt.members.iter().enumerate() {
        let decl = guarded(|| {
            named_decl(
                member.name.as_ref().map(|n| n.as_bytes()),
                &member.member_type,
                solver,
            )
            .map_err(Into::into)
        });
        if decl.is_err() {
            counts.decl_errors += 1;
        }
        let lay = layout.get(i);
        stmt.execute(params![
            til_id,
            type_name,
            i as i64,
            member.name.as_ref().map(|n| n.as_utf8_lossy()),
            decl.ok(),
            lay.map(|l| l.offset as i64),
            lay.and_then(|l| l.bit_offset.map(|b| b as i64)),
            lay.map(|l| l.size as i64),
            member.comment.as_ref().map(|c| format!("{c:?}")),
        ])?;
        counts.members += 1;
    }
    Ok(())
}

fn insert_enum_values(
    tx: &Transaction,
    til_id: i64,
    enum_name: &str,
    en: &Enum,
    counts: &mut TilCounts,
) -> Result<()> {
    let mut stmt = tx.prepare_cached(
        "INSERT INTO til_enum_values (til_id, enum_name, name, value,
            group_name, comment)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    let mut insert = |member: &EnumMember, group: Option<&str>| -> Result<()> {
        stmt.execute(params![
            til_id,
            enum_name,
            member.name.as_ref().map(|n| n.as_utf8_lossy()),
            member.value as i64,
            group,
            member.comment.as_ref().map(|c| format!("{c:?}")),
        ])?;
        counts.enum_values += 1;
        Ok(())
    };
    let groups = match &en.members {
        EnumMembers::Regular(list) => {
            return list.iter().try_for_each(|m| insert(m, None));
        }
        EnumMembers::Groups(groups) => groups,
    };
    for group in groups {
        let group_name = group
            .field
            .name
            .as_ref()
            .map(|n| n.as_utf8_lossy().into_owned());
        insert(&group.field, None)?;
        for member in &group.sub_fields {
            insert(member, group_name.as_deref())?;
        }
    }
    Ok(())
}

fn insert_symbols(
    tx: &Transaction,
    til_id: i64,
    til: &TILSection,
    solver: &mut TILTypeSizeSolver<'_>,
    counts: &mut TilCounts,
) -> Result<()> {
    let mut stmt = tx.prepare(
        "INSERT INTO til_symbols (til_id, value, name, sclass, decl)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for symbol in &til.symbols {
        let decl = guarded(|| symbol_decl(symbol, solver).map_err(Into::into));
        if decl.is_err() {
            counts.decl_errors += 1;
        }
        stmt.execute(params![
            til_id,
            symbol.ordinal as i64,
            symbol.name.as_utf8_lossy(),
            sclass_name(symbol.sclass),
            decl.ok(),
        ])?;
        counts.symbols += 1;
    }
    Ok(())
}

fn insert_macros(
    tx: &Transaction,
    til_id: i64,
    til: &TILSection,
    counts: &mut TilCounts,
) -> Result<()> {
    let mut stmt = tx.prepare(
        "INSERT INTO til_macros (til_id, name, param_count, value)
         VALUES (?1, ?2, ?3, ?4)",
    )?;
    for mac in til.macros.iter().flatten() {
        let value: String = mac
            .value
            .iter()
            .map(|c| match c {
                TILMacroValue::Char(c) => (*c as char).to_string(),
                TILMacroValue::Param(p) => format!("{{P{p}}}"),
            })
            .collect();
        stmt.execute(params![
            til_id,
            mac.name.as_utf8_lossy(),
            mac.param_num,
            value
        ])?;
        counts.macros += 1;
    }
    Ok(())
}

pub fn open_new_db(path: &Path) -> Result<Connection> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF;
         PRAGMA temp_store = MEMORY; PRAGMA cache_size = -1000000;",
    )?;
    Ok(conn)
}

fn collect_til_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(path)?
            .map(|e| e.map(|e| e.path()))
            .collect::<std::io::Result<_>>()?;
        entries.sort();
        for entry in entries {
            collect_til_files(&entry, out)?;
        }
    } else if path.extension().is_some_and(|e| e == "til") {
        out.push(path.to_path_buf());
    }
    Ok(())
}

pub fn export_til_sqlite(args: &ExportTilSqliteArgs) -> Result<()> {
    let started = std::time::Instant::now();
    let mut files = Vec::new();
    for input in &args.inputs {
        collect_til_files(input, &mut files)?;
    }
    let mut conn = open_new_db(&args.output)?;
    let tx = conn.transaction()?;
    tx.execute_batch(TIL_SCHEMA)?;
    let mut total = TilCounts::default();
    let mut failed = 0;
    for file in &files {
        let display = file.to_string_lossy();
        let parsed = File::open(file)
            .map_err(anyhow::Error::from)
            .and_then(|f| guarded(|| TILSection::read(&mut BufReader::new(f))));
        match parsed {
            Ok(til) => {
                let id = insert_til_header(&tx, &display, Some(&til), None)?;
                let counts = insert_til(&tx, id, &til)?;
                total.types += counts.types;
                total.symbols += counts.symbols;
                total.members += counts.members;
                total.enum_values += counts.enum_values;
                total.macros += counts.macros;
                total.decl_errors += counts.decl_errors;
            }
            Err(err) => {
                failed += 1;
                eprintln!("{display}: {err:#}");
                insert_til_header(
                    &tx,
                    &display,
                    None,
                    Some(&format!("{err:#}")),
                )?;
            }
        }
    }
    tx.execute_batch(TIL_INDEXES)?;
    tx.commit()?;
    eprintln!(
        "{} til files ({failed} failed to parse): {} types, {} members, \
         {} enum values, {} symbols, {} macros, {} declarations failed to \
         render, {:.1}s",
        files.len(),
        total.types,
        total.members,
        total.enum_values,
        total.symbols,
        total.macros,
        total.decl_errors,
        started.elapsed().as_secs_f64(),
    );
    Ok(())
}
