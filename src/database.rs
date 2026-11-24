//! A whole database read once into plain values: the segments and their bytes,
//! functions with names, flags and C prototypes, names, comments and local types.
//!
//! This is the view a tool that is not IDA needs to reuse an analysis, so every
//! address is a `u64` and every type is rendered as C text (`tilib` style).
//! Parse errors of single items are collected in [`Database::errors`] and the
//! item is skipped; a panic inside the parser or the type printer is caught.

use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Seek};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde::Serialize;

use crate::addr_info::AddressInfo;
use crate::bytes_info::BytesInfo;
use crate::id0::function::IDBFunctionType;
use crate::id0::{ID0Section, Netdelta, RootInfo};
use crate::id1::ID1Section;
use crate::id2::ID2Section;
use crate::nam::NamSection;
use crate::til::print::{named_decl, type_decl};
use crate::til::section::TILSection;
use crate::til::{TILTypeSizeSolver, Type};
use crate::{
    identify_idb_file, Address, IDAKind, IDAUsize, IDAVariants, IDBFormat,
    IDBFormats,
};

/// The largest segment whose bytes [`Database::memory`] holds; a larger one
/// is listed but not loaded.
pub const MAX_SEGMENT_BYTES: u64 = 256 << 20;
/// At most this many item errors are kept.
const MAX_ERRORS: usize = 64;

/// What to read besides the analysis itself.
#[derive(Clone, Copy, Debug, Default)]
pub struct Load {
    /// Read every segment's bytes into [`Database::memory`].
    pub memory: bool,
}

/// The database-wide facts.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Info {
    /// IDA's processor module name (`metapc`, `ARM`, `mipsl`, ...).
    pub processor: String,
    /// The width of an address in the database: 32 (`.idb`) or 64 (`.i64`).
    pub address_bits: u32,
    /// The program's own bitness: 16, 32 or 64.
    pub bitness: u32,
    pub big_endian: bool,
    /// The database format version (6 is IDA 6/7/8, 910 and 950 IDA 9).
    pub version: u16,
    /// The input file format as IDA's loader named it (`Elf`, `Pe`, `MachO`, ...).
    pub file_format: String,
    /// The compiler IDA assumed (`Gnu`, `VisualStudio`, ...).
    pub compiler: String,
    pub input_file: Option<String>,
    pub input_size: Option<u64>,
    pub input_crc32: Option<u32>,
    pub input_md5: Option<String>,
    pub input_sha256: Option<String>,
    pub image_base: Option<u64>,
}

/// Read, write and execute rights.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Perms {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// One segment.
#[derive(Clone, Debug, Serialize)]
pub struct Segment {
    pub start: u64,
    pub end: u64,
    pub name: Option<String>,
    pub class: Option<String>,
    /// `None` when the database records no rights.
    pub perms: Option<Perms>,
    /// 16, 32 or 64.
    pub bitness: u32,
    /// The segment type: `norm`, `xtrn`, `code`, `data`, `bss`, ...
    pub kind: String,
}

/// One function (its entry chunk), with the tails it owns.
#[derive(Clone, Debug, Serialize)]
pub struct Function {
    pub start: u64,
    /// The end of the entry chunk.
    pub end: u64,
    /// The name; `sub_<HEX>` when the database holds none.
    pub name: String,
    /// The database holds a name for it (a user or loader name, not a dummy).
    pub named: bool,
    pub no_return: bool,
    pub library: bool,
    pub thunk: bool,
    /// The C prototype with the function's name as declarator.
    pub prototype: Option<String>,
    pub comment: Option<String>,
    pub repeatable_comment: Option<String>,
    /// The other chunks, `(start, end)`.
    pub tails: Vec<(u64, u64)>,
}

/// A named address.
#[derive(Clone, Debug, Serialize)]
pub struct Name {
    pub address: u64,
    pub name: String,
}

/// Where a comment shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CommentKind {
    Regular,
    Repeatable,
    /// A line before the item.
    Anterior,
    /// A line after the item.
    Posterior,
}

/// One comment on an item.
#[derive(Clone, Debug, Serialize)]
pub struct Comment {
    pub address: u64,
    pub kind: CommentKind,
    pub text: String,
}

/// A local type, rendered as one C declaration ending in `;`.
#[derive(Clone, Debug, Serialize)]
pub struct LocalType {
    pub ordinal: u64,
    pub name: String,
    pub declaration: String,
}

/// An entry point (export, program entry).
#[derive(Clone, Debug, Serialize)]
pub struct EntryPoint {
    pub address: u64,
    pub name: String,
    pub forwarded: Option<String>,
}

/// Loaded bytes of one segment; bytes the database does not hold read as zero.
#[derive(Clone, Debug)]
pub struct MemoryRun {
    pub start: u64,
    pub bytes: Vec<u8>,
    /// The rights of the segment the run comes from.
    pub perms: Perms,
}

/// A database's contents.
#[derive(Clone, Debug, Default)]
pub struct Database {
    pub info: Info,
    pub segments: Vec<Segment>,
    /// Address-ordered.
    pub functions: Vec<Function>,
    /// Address-ordered.
    pub names: Vec<Name>,
    /// Address-ordered.
    pub comments: Vec<Comment>,
    pub types: Vec<LocalType>,
    pub entry_points: Vec<EntryPoint>,
    /// Filled when [`Load::memory`] is set; address-ordered and disjoint.
    pub memory: Vec<MemoryRun>,
    /// Items that did not parse and were skipped, at most 64.
    pub errors: Vec<String>,
}

impl Database {
    /// Read the `.idb`/`.i64` at `path`.
    pub fn open(path: impl AsRef<Path>, load: Load) -> Result<Self> {
        let path = path.as_ref();
        let file = File::open(path)
            .with_context(|| format!("open {}", path.display()))?;
        Self::read(BufReader::new(file), load)
    }

    /// Read a database from `input`.
    pub fn read<I: BufRead + Seek>(mut input: I, load: Load) -> Result<Self> {
        catch_unwind(AssertUnwindSafe(|| read_any(&mut input, load)))
            .unwrap_or_else(|_| Err(anyhow!("the IDB parser panicked")))
    }

    /// Does `bytes` start like an IDA database (`IDA0`, `IDA1`, `IDA2`)?
    pub fn is_database(bytes: &[u8]) -> bool {
        matches!(bytes.get(..4), Some(b"IDA0" | b"IDA1" | b"IDA2"))
    }
}

fn read_any<I: BufRead + Seek>(input: &mut I, load: Load) -> Result<Database> {
    match identify_idb_file(&mut *input)? {
        IDBFormats::Separated(IDAVariants::IDA32(sections)) => {
            read_format(sections, input, load)
        }
        IDBFormats::Separated(IDAVariants::IDA64(sections)) => {
            read_format(sections, input, load)
        }
        IDBFormats::InlineUncompressed(sections) => {
            read_format(sections, input, load)
        }
        IDBFormats::InlineCompressed(compressed) => {
            let mut decompressed = Vec::new();
            let sections = compressed
                .decompress_into_memory(&mut *input, &mut decompressed)?;
            read_format(sections, Cursor::new(&decompressed[..]), load)
        }
    }
}

struct Sections<K: IDAKind> {
    id0: ID0Section<K>,
    id1: ID1Section<K>,
    id2: Option<ID2Section<K>>,
    nam: Option<NamSection<K>>,
    til: Option<TILSection>,
}

fn read_format<K: IDAKind, F: IDBFormat<K>, I: BufRead + Seek>(
    idb: F,
    mut input: I,
    load: Load,
) -> Result<Database> {
    let id0 = idb
        .id0_location()
        .ok_or_else(|| anyhow!("no ID0 section"))?;
    let id1 = idb
        .id1_location()
        .ok_or_else(|| anyhow!("no ID1 section"))?;
    let id2 = idb.id2_location();
    let nam = idb.nam_location();
    let til = idb.til_location();
    let s = Sections {
        id0: idb.read_id0(&mut input, id0).context("read ID0")?,
        id1: idb.read_id1(&mut input, id1).context("read ID1")?,
        id2: id2
            .map(|l| idb.read_id2(&mut input, l))
            .transpose()
            .context("read ID2")?,
        nam: nam
            .map(|l| idb.read_nam(&mut input, l))
            .transpose()
            .context("read NAM")?,
        til: til
            .map(|l| idb.read_til(&mut input, l))
            .transpose()
            .context("read TIL")?,
    };
    Reader::new(&s)?.read(load)
}

fn u<K: IDAKind>(address: Address<K>) -> u64 {
    address.into_raw().into_u64()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn guarded<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    catch_unwind(AssertUnwindSafe(f))
        .unwrap_or_else(|_| Err(anyhow!("the type printer panicked")))
}

struct Reader<'a, K: IDAKind> {
    s: &'a Sections<K>,
    root: RootInfo<K>,
    netdelta: Netdelta<K>,
    errors: Vec<String>,
}

impl<'a, K: IDAKind> Reader<'a, K> {
    fn new(s: &'a Sections<K>) -> Result<Self> {
        let root = s.id0.ida_info(s.id0.root_node()?)?;
        let netdelta = root.netdelta();
        Ok(Self {
            s,
            root,
            netdelta,
            errors: Vec::new(),
        })
    }

    fn error(&mut self, what: &str, err: impl std::fmt::Display) {
        if self.errors.len() < MAX_ERRORS {
            self.errors.push(format!("{what}: {err:#}"));
        }
    }

    fn read(mut self, load: Load) -> Result<Database> {
        let info = self.info()?;
        let segments = self.segments()?;
        let mut solver = self.s.til.as_ref().map(TILTypeSizeSolver::new);
        let functions = self.functions(solver.as_mut())?;
        let names = self.names();
        let comments = self.comments();
        let types = self.types(solver.as_mut());
        let entry_points = self.entry_points();
        let memory = if load.memory {
            self.memory(&segments)
        } else {
            Vec::new()
        };
        Ok(Database {
            info,
            segments,
            functions,
            names,
            comments,
            types,
            entry_points,
            memory,
            errors: self.errors,
        })
    }

    fn info(&mut self) -> Result<Info> {
        let id0 = &self.s.id0;
        let idx = id0.root_node()?;
        let root = &self.root;
        let bitness = if root.lflags.is_program_64b() {
            64
        } else if root.lflags.is_program_32b_or_bigger() {
            32
        } else {
            16
        };
        let mut info = Info {
            processor: String::from_utf8_lossy(&root.target.processor)
                .trim_end_matches('\0')
                .to_string(),
            address_bits: u32::from(K::BYTES) * 8,
            bitness,
            big_endian: root.lflags.is_big_endian(),
            version: root.version,
            file_format: format!("{:?}", root.input.file_format),
            compiler: format!("{:?}", root.compiler.compiler),
            input_file: id0
                .input_file(idx)
                .map(|f| f.as_utf8_lossy().into_owned()),
            ..Info::default()
        };
        match id0.input_file_size(idx) {
            Ok(v) => info.input_size = v.map(IDAUsize::into_u64),
            Err(e) => self.error("input file size", e),
        }
        match id0.input_file_crc32(idx) {
            Ok(v) => info.input_crc32 = v,
            Err(e) => self.error("input file crc32", e),
        }
        match id0.input_file_md5(idx) {
            Ok(v) => info.input_md5 = v.map(|v| hex(v)),
            Err(e) => self.error("input file md5", e),
        }
        match id0.input_file_sha256(idx) {
            Ok(v) => info.input_sha256 = v.map(|v| hex(v)),
            Err(e) => self.error("input file sha256", e),
        }
        match id0.image_base(idx) {
            Ok(v) => info.image_base = v.map(u),
            Err(e) => self.error("image base", e),
        }
        Ok(info)
    }

    fn segments(&mut self) -> Result<Vec<Segment>> {
        let id0 = &self.s.id0;
        let mut names = std::collections::BTreeMap::new();
        if let Some(idx) = id0.segment_strings_idx()? {
            for entry in id0.segment_strings(idx) {
                match entry {
                    Ok((name_idx, name)) => {
                        names.insert(
                            name_idx.0.into_u64(),
                            name.as_utf8_lossy().into_owned(),
                        );
                    }
                    Err(e) => self.error("segment name", e),
                }
            }
        }
        let mut out = Vec::new();
        if let Some(idx) = id0.segments_idx()? {
            for seg in id0.segments(idx) {
                let seg = match seg {
                    Ok(seg) => seg,
                    Err(e) => {
                        self.error("segment", e);
                        continue;
                    }
                };
                out.push(Segment {
                    start: u(seg.address.start),
                    end: u(seg.address.end),
                    name: names.get(&seg.name.0.into_u64()).cloned(),
                    class: names.get(&seg.class_id.0.into_u64()).cloned(),
                    perms: seg.perm.map(|p| Perms {
                        read: p.can_read(),
                        write: p.can_write(),
                        execute: p.can_execute(),
                    }),
                    bitness: match seg.bitness {
                        crate::id0::SegmentBitness::S16Bits => 16,
                        crate::id0::SegmentBitness::S32Bits => 32,
                        crate::id0::SegmentBitness::S64Bits => 64,
                    },
                    kind: format!("{:?}", seg.seg_type).to_lowercase(),
                });
            }
        }
        out.sort_by_key(|s| s.start);
        Ok(out)
    }

    fn label(&mut self, address: Address<K>) -> Option<String> {
        let info =
            AddressInfo::new_forced(&self.s.id0, self.netdelta, address)?;
        match info.label() {
            Ok(label) => label
                .map(|l| l.as_utf8_lossy().into_owned())
                .filter(|l| !l.is_empty()),
            Err(e) => {
                self.error(&format!("name at {:#x}", u(address)), e);
                None
            }
        }
    }

    fn tinfo(&mut self, address: Address<K>) -> Option<Type> {
        let s = self.s;
        let info = AddressInfo::new(
            &s.id0,
            &s.id1,
            s.id2.as_ref(),
            self.netdelta,
            address,
        )?;
        match guarded(|| info.tinfo(&self.root)) {
            Ok(ty) => ty,
            Err(e) => {
                self.error(&format!("type at {:#x}", u(address)), e);
                None
            }
        }
    }

    fn functions(
        &mut self,
        mut solver: Option<&mut TILTypeSizeSolver<'_>>,
    ) -> Result<Vec<Function>> {
        let id0 = &self.s.id0;
        let Some(funcs_idx) = id0.funcs_idx()? else {
            return Ok(Vec::new());
        };
        let mut out: Vec<Function> = Vec::new();
        let mut tails: Vec<(u64, u64, u64)> = Vec::new();
        for func in id0.fchunks(funcs_idx) {
            let func = match func {
                Ok(func) => func,
                Err(e) => {
                    self.error("function", e);
                    continue;
                }
            };
            let start = func.address.start;
            if let IDBFunctionType::Tail(tail) = &func.extra {
                tails.push((u(tail.owner), u(start), u(func.address.end)));
                continue;
            }
            let label = self.label(start);
            let named = label.is_some();
            let name = label.unwrap_or_else(|| format!("sub_{:X}", u(start)));
            let prototype = match (self.tinfo(start), solver.as_deref_mut()) {
                (Some(ty), Some(solver)) => {
                    match guarded(|| {
                        named_decl(Some(name.as_bytes()), &ty, solver)
                            .map_err(Into::into)
                    }) {
                        Ok(decl) => Some(decl),
                        Err(e) => {
                            self.error(
                                &format!("prototype at {:#x}", u(start)),
                                e,
                            );
                            None
                        }
                    }
                }
                _ => None,
            };
            let text = |r: Result<Option<crate::IDBString>>| {
                r.ok()
                    .flatten()
                    .map(|c| c.as_utf8_lossy().trim_end().to_string())
                    .filter(|c| !c.is_empty())
            };
            let comment = text(id0.func_cmt(funcs_idx, self.netdelta, start));
            let repeatable_comment =
                text(id0.func_repeatable_cmt(funcs_idx, self.netdelta, start));
            out.push(Function {
                start: u(start),
                end: u(func.address.end),
                name,
                named,
                no_return: func.flags.is_no_return(),
                library: func.flags.is_lib(),
                thunk: func.flags.is_thunk(),
                prototype,
                comment,
                repeatable_comment,
                tails: Vec::new(),
            });
        }
        out.sort_by_key(|f| f.start);
        out.dedup_by_key(|f| f.start);
        for (owner, start, end) in tails {
            if let Ok(i) = out.binary_search_by_key(&owner, |f| f.start) {
                out[i].tails.push((start, end));
            }
        }
        for f in &mut out {
            f.tails.sort_unstable();
        }
        Ok(out)
    }

    fn names(&mut self) -> Vec<Name> {
        let Some(nam) = &self.s.nam else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for &address in &nam.names {
            if let Some(name) = self.label(address) {
                out.push(Name {
                    address: u(address),
                    name,
                });
            }
        }
        out.sort_by_key(|n| n.address);
        out.dedup_by_key(|n| n.address);
        out
    }

    fn comments(&mut self) -> Vec<Comment> {
        let s = self.s;
        let bytes = BytesInfo::new(Some(&s.id1), s.id2.as_ref());
        let mut out = Vec::new();
        for (address, byte, _) in bytes.heads() {
            if !byte.has_comment() && !byte.has_comment_ext() {
                continue;
            }
            let Some(info) = AddressInfo::new(
                &s.id0,
                &s.id1,
                s.id2.as_ref(),
                self.netdelta,
                address,
            ) else {
                continue;
            };
            let at = u(address);
            let mut push = |kind, text: crate::IDBStr<'_>| {
                let text = text.as_utf8_lossy().trim_end().to_string();
                if !text.is_empty() {
                    out.push(Comment {
                        address: at,
                        kind,
                        text,
                    });
                }
            };
            if byte.has_comment() {
                if let Some(c) = info.comment() {
                    push(CommentKind::Regular, c);
                }
                if let Some(c) = info.comment_repeatable() {
                    push(CommentKind::Repeatable, c);
                }
            }
            if let Some(lines) = info.comment_pre() {
                for line in lines {
                    push(CommentKind::Anterior, line);
                }
            }
            if let Some(lines) = info.comment_post() {
                for line in lines {
                    push(CommentKind::Posterior, line);
                }
            }
        }
        out.sort_by_key(|c| c.address);
        out
    }

    fn types(
        &mut self,
        solver: Option<&mut TILTypeSizeSolver<'_>>,
    ) -> Vec<LocalType> {
        let (Some(til), Some(solver)) = (&self.s.til, solver) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (idx, ty) in til.types.iter().enumerate() {
            let name = ty.name.as_bytes();
            if name.is_empty() {
                continue;
            }
            match guarded(|| {
                type_decl(name, idx, &ty.tinfo, solver).map_err(Into::into)
            }) {
                Ok(declaration) => out.push(LocalType {
                    ordinal: ty.ordinal,
                    name: ty.name.as_utf8_lossy().into_owned(),
                    declaration,
                }),
                Err(e) => self.error(
                    &format!("local type {}", ty.name.as_utf8_lossy()),
                    e,
                ),
            }
        }
        out
    }

    fn entry_points(&mut self) -> Vec<EntryPoint> {
        match self.s.id0.entry_points(&self.root) {
            Ok(entries) => {
                let mut out: Vec<EntryPoint> = entries
                    .into_iter()
                    .map(|e| EntryPoint {
                        address: e.address.into_u64(),
                        name: e.name,
                        forwarded: e.forwarded,
                    })
                    .collect();
                out.sort_by_key(|e| e.address);
                out
            }
            Err(e) => {
                self.error("entry points", e);
                Vec::new()
            }
        }
    }

    fn memory(&mut self, segments: &[Segment]) -> Vec<MemoryRun> {
        let s = self.s;
        let bytes = BytesInfo::new(Some(&s.id1), s.id2.as_ref());
        let mut out: Vec<MemoryRun> = Vec::new();
        for seg in segments {
            let size = seg.end.saturating_sub(seg.start);
            if size == 0 {
                continue;
            }
            if size > MAX_SEGMENT_BYTES {
                self.error(
                    &format!("segment {:#x}..{:#x}", seg.start, seg.end),
                    "too large to load",
                );
                continue;
            }
            if out.last().is_some_and(|last| {
                last.start + last.bytes.len() as u64 > seg.start
            }) {
                self.error(
                    &format!("segment {:#x}..{:#x}", seg.start, seg.end),
                    "overlaps the segment before it",
                );
                continue;
            }
            let mut data = vec![0u8; size as usize];
            let mut any = false;
            for (i, slot) in data.iter_mut().enumerate() {
                let Ok(at) = K::Usize::try_from(seg.start + i as u64) else {
                    break;
                };
                if let Some(b) = bytes
                    .byte_by_address(Address::from_raw(at))
                    .and_then(|b| b.data())
                {
                    *slot = b;
                    any = true;
                }
            }
            let perms = seg.perms.unwrap_or(Perms {
                read: true,
                write: !matches!(seg.kind.as_str(), "code"),
                execute: matches!(seg.kind.as_str(), "code"),
            });
            if any || seg.kind == "bss" || perms.write {
                out.push(MemoryRun {
                    start: seg.start,
                    bytes: data,
                    perms,
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resource(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("resources/idbs")
            .join(name)
    }

    #[test]
    fn reads_every_resource_database() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("resources/idbs");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return;
        };
        let mut paths: Vec<_> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "i64" || e == "idb"))
            .collect();
        paths.sort();
        for path in paths {
            let db = Database::open(&path, Load { memory: true })
                .unwrap_or_else(|e| panic!("{}: {e:#}", path.display()));
            let protos = db
                .functions
                .iter()
                .filter(|f| f.prototype.is_some())
                .count();
            let loaded: usize = db.memory.iter().map(|r| r.bytes.len()).sum();
            eprintln!(
                "{}: {} {}-bit, {} segments, {} functions ({protos} typed), {} names, {} comments, {} types, {} bytes, {} errors {:?}",
                path.file_name().unwrap().to_string_lossy(),
                db.info.processor,
                db.info.bitness,
                db.segments.len(),
                db.functions.len(),
                db.names.len(),
                db.comments.len(),
                db.types.len(),
                loaded,
                db.errors.len(),
                db.errors.first(),
            );
            assert!(db.functions.windows(2).all(|w| w[0].start < w[1].start));
            assert!(db
                .memory
                .windows(2)
                .all(|w| w[0].start + w[0].bytes.len() as u64 <= w[1].start));
        }
    }

    #[test]
    fn function_bytes_come_from_id1() {
        let path = resource("cat.i64");
        if !path.exists() {
            return;
        }
        let db = Database::open(&path, Load { memory: true }).unwrap();
        assert_eq!(db.info.processor, "metapc");
        assert_eq!(db.info.bitness, 64);
        let main = db
            .functions
            .iter()
            .find(|f| f.name == "main")
            .expect("main");
        let run = db
            .memory
            .iter()
            .find(|r| {
                r.start <= main.start
                    && main.start < r.start + r.bytes.len() as u64
            })
            .expect("main is loaded");
        assert!(run.perms.execute);
        assert!(!db.is_empty_prototypes());
    }

    #[test]
    fn recognizes_the_magic() {
        assert!(Database::is_database(b"IDA1\0\0"));
        assert!(Database::is_database(b"IDA2"));
        assert!(!Database::is_database(b"\x7fELF"));
        assert!(!Database::is_database(b"ID"));
    }

    impl Database {
        fn is_empty_prototypes(&self) -> bool {
            self.functions.iter().all(|f| f.prototype.is_none())
        }
    }
}
