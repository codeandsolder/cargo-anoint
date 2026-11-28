//! Discover statically named out-of-line modules from Cargo target roots.
//!
//! Rust resolves explicit paths differently from ordinary module names:
//! <https://doc.rust-lang.org/reference/items/modules.html#module-source-filenames>

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use syn::punctuated::Punctuated;
use syn::{Expr, Lit, Meta, Token};
use tree_sitter::{Node, Parser};

use crate::code_audit::{CodeAuditConfig, is_ignored_path, is_test_attr, read_source, rust_parser};

#[derive(Eq, Hash, PartialEq)]
struct ModuleFile {
    path: PathBuf,
    /// Default submodules of a non-mod.rs file live under its stem.
    default_dir: PathBuf,
}

impl ModuleFile {
    fn explicit(path: PathBuf) -> Result<Self> {
        let default_dir = path
            .parent()
            .context("module file has no parent")?
            .to_path_buf();
        Ok(Self { path, default_dir })
    }
}

pub fn discover(
    roots: BTreeSet<PathBuf>,
    package_root: &Path,
    config: &CodeAuditConfig,
    files: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    let mut pending = roots
        .into_iter()
        .map(ModuleFile::explicit)
        .collect::<Result<Vec<_>>>()?;
    let mut visited = HashSet::new();
    let mut parser = rust_parser()?;
    while let Some(mut module) = pending.pop() {
        if is_ignored_path(
            module
                .path
                .strip_prefix(package_root)
                .unwrap_or(&module.path),
            config,
        ) || !module.path.try_exists()?
        {
            continue;
        }
        let identity = module.path.canonicalize()?;
        // Normalize directory contexts to prevent alternate spellings of cycles.
        module.path = normalize_directory_entry(&module.path)?;
        module.default_dir = if module.default_dir.try_exists()? {
            module.default_dir.canonicalize()?
        } else {
            normalize_directory_entry(&module.default_dir)?
        };
        if is_ignored_path(
            identity.strip_prefix(package_root).unwrap_or(&identity),
            config,
        ) {
            continue;
        }
        if !visited.insert((module.path.clone(), module.default_dir.clone())) {
            continue;
        }
        let code = read_source(&identity, config)?;
        files.insert(identity);
        pending.extend(children(&mut parser, &module, &code, config.include_tests)?);
    }
    Ok(())
}

fn normalize_directory_entry(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .context("module path has no parent")?
        .canonicalize()?;
    Ok(parent.join(path.file_name().context("module path has no filename")?))
}

#[derive(Default)]
struct ModuleAttrs {
    paths: Vec<PathBuf>,
    has_direct_path: bool,
    test_only: bool,
}

impl ModuleAttrs {
    fn add(&mut self, node: Node<'_>, code: &[u8]) {
        self.test_only |= is_test_attr(node, code);
        if let Some(attribute) = node.named_child(0)
            && let Ok(text) = attribute.utf8_text(code)
            && attribute
                .named_child(0)
                .and_then(|name| name.utf8_text(code).ok())
                .is_some_and(|name| matches!(name, "path" | "cfg_attr"))
            && let Ok(meta) = syn::parse_str::<Meta>(text)
        {
            self.collect_paths(meta);
        }
    }

    fn collect_paths(&mut self, meta: Meta) {
        let mut pending = vec![(meta, false)];
        while let Some((meta, conditional)) = pending.pop() {
            match meta {
                Meta::NameValue(value) if value.path.is_ident("path") => {
                    if let Expr::Lit(literal) = value.value
                        && let Lit::Str(path) = literal.lit
                    {
                        self.paths.push(PathBuf::from(path.value()));
                        self.has_direct_path |= !conditional;
                    }
                }
                Meta::List(list) if list.path.is_ident("cfg_attr") => {
                    if let Ok(items) =
                        list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                    {
                        pending.extend(items.into_iter().skip(1).map(|item| (item, true)));
                    }
                }
                _ => {}
            }
        }
    }
}

fn children(
    parser: &mut Parser,
    module: &ModuleFile,
    code: &str,
    include_tests: bool,
) -> Result<Vec<ModuleFile>> {
    let tree = parser
        .parse(code, None)
        .context("parse Rust module declarations")?;
    let explicit_dir = module.path.parent().context("module file has no parent")?;
    let mut lists = vec![(
        tree.root_node(),
        explicit_dir.to_path_buf(),
        module.default_dir.clone(),
    )];
    let mut discovered = Vec::new();
    while let Some((list, explicit_dir, default_dir)) = lists.pop() {
        let mut attrs = ModuleAttrs::default();
        for item in list.named_children(&mut list.walk()) {
            match item.kind() {
                "attribute_item" => attrs.add(item, code.as_bytes()),
                "line_comment" | "block_comment" | "inner_attribute_item" => {}
                _ => {
                    if item.kind() == "mod_item" && (include_tests || !attrs.test_only) {
                        let name = item
                            .child_by_field_name("name")
                            .context("module has no name")?
                            .utf8_text(code.as_bytes())?;
                        let name = name.strip_prefix("r#").unwrap_or(name);
                        if let Some(body) = item.child_by_field_name("body") {
                            for path in attrs
                                .paths
                                .iter()
                                .map(|path| explicit_dir.join(path))
                                .chain((!attrs.has_direct_path).then(|| default_dir.join(name)))
                            {
                                lists.push((body, path.clone(), path));
                            }
                        } else {
                            discovered.extend(module_files(
                                &attrs,
                                &explicit_dir,
                                &default_dir,
                                name,
                            )?);
                        }
                    }
                    attrs = ModuleAttrs::default();
                }
            }
        }
    }
    Ok(discovered)
}

fn module_files(
    attrs: &ModuleAttrs,
    explicit_dir: &Path,
    default_dir: &Path,
    name: &str,
) -> Result<Vec<ModuleFile>> {
    let mut files = attrs
        .paths
        .iter()
        .map(|path| ModuleFile::explicit(explicit_dir.join(path)))
        .collect::<Result<Vec<_>>>()?;
    if !attrs.has_direct_path {
        let directory = default_dir.join(name);
        files.push(ModuleFile {
            path: default_dir.join(format!("{name}.rs")),
            default_dir: directory.clone(),
        });
        files.push(ModuleFile {
            path: directory.join("mod.rs"),
            default_dir: directory,
        });
    }
    Ok(files)
}
