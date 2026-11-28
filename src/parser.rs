//! Parser layer — extracts the full dependency tree from Cargo.toml / Cargo.lock
//! using `cargo_metadata` for feature-aware resolution.

use anyhow::{Result, bail};
use cargo_metadata::{
    CargoOpt, DepKindInfo, DependencyKind, MetadataCommand, Node, NodeDep, Package, PackageId,
    Resolve,
};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};

/// A resolved dependency with its name, version, and enabled features.
#[derive(Debug, Clone)]
pub struct ResolvedDep {
    pub name: String,
    pub version: String,
    /// Features that are **actually enabled** in the resolved build plan.
    pub enabled_features: Vec<String>,
    /// All features **declared** by the crate (available but not necessarily enabled).
    pub available_features: Vec<String>,
    pub source: Option<String>,
    pub repository: Option<String>,
    pub is_direct: bool,
    pub direct_kinds: Vec<DependencyKind>,
}

/// One Cargo package in the workspace (or the resolved root crate) plus its dependency tree.
///
/// Produced before suggestion analysis runs; see Phase 3 workspace design (`docs/`).
#[derive(Debug, Clone)]
pub struct PackageResult {
    pub name: String,
    pub version: String,
    pub manifest_path: PathBuf,
    pub deps: Vec<ResolvedDep>,
}

impl fmt::Display for ResolvedDep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag = if self.is_direct {
            "direct"
        } else {
            "transitive"
        };
        write!(f, "{} v{} ({tag})", self.name, self.version)?;
        if !self.enabled_features.is_empty() {
            write!(f, " [enabled: {}]", self.enabled_features.join(", "))?;
        }
        if !self.available_features.is_empty() && self.available_features != self.enabled_features {
            write!(f, " (available: {})", self.available_features.join(", "))?;
        }
        Ok(())
    }
}

/// Get the root project's name and version from Cargo metadata.
///
/// # Errors
/// Returns an error if Cargo metadata fails or no root package can be resolved.
pub fn get_project_info(manifest_path: Option<&Path>) -> Result<(String, String)> {
    let cmd = metadata_command(manifest_path);
    let metadata = cmd.exec()?;
    let root_id = metadata
        .resolve
        .as_ref()
        .and_then(|r| r.root.as_ref())
        .ok_or_else(|| anyhow::anyhow!("No root package found"))?;
    let root_pkg = metadata
        .packages
        .iter()
        .find(|p| &p.id == root_id)
        .ok_or_else(|| anyhow::anyhow!("Root package not in packages list"))?;
    Ok((root_pkg.name.to_string(), root_pkg.version.to_string()))
}

/// Build a lookup from package ID to the resolved Node (which carries enabled features).
fn build_node_lookup(resolve: &Resolve) -> HashMap<String, Node> {
    resolve
        .nodes
        .iter()
        .map(|n| (n.id.to_string(), n.clone()))
        .collect()
}

/// Build a map from package ID to package reference.
fn build_pkg_lookup(metadata: &cargo_metadata::Metadata) -> HashMap<String, Package> {
    metadata
        .packages
        .iter()
        .map(|p| (p.id.to_string(), p.clone()))
        .collect()
}

/// Parse the dependency tree for the project at `manifest_path` (resolved root crate only).
///
/// **Key change**: uses `resolve.nodes[].features` for the **actual enabled features**
/// rather than `pkg.features.keys()` which only lists declared/available features.
///
/// # Errors
/// Returns an error if metadata resolution fails or no root snapshot exists.
pub fn get_deps(manifest_path: Option<&Path>) -> Result<Vec<ResolvedDep>> {
    let snapshots = fetch_metadata_and_snapshots(
        manifest_path,
        SnapshotMode::RootOnly,
        false,
        &ResolutionOptions::default(),
    )?;
    snapshots
        .into_iter()
        .next()
        .map(|p| p.deps)
        .ok_or_else(|| anyhow::anyhow!("No dependency snapshot produced"))
}

/// Load dependency snapshots for workspace members according to Cargo metadata.
///
/// - **Root-only**: `workspace_all_members` false and `package_filters` empty — only `[package]` at the resolved root (`resolve.root`).
/// - **All members**: `workspace_all_members` true — every entry in `metadata.workspace_members`.
/// - **Filtered**: non-empty `package_filters` — members whose names match case-insensitively (comma-separated CLI values become one slice).
///
/// `all_targets` widens what counts as a "direct" dep to include `[dev-dependencies]` and
/// `[build-dependencies]` in addition to normal `[dependencies]`.
#[derive(Debug, Default)]
pub struct ResolutionOptions {
    pub all_features: bool,
    pub features: Vec<String>,
    pub no_default_features: bool,
    pub target: Option<String>,
}

///
/// # Errors
/// Returns an error if metadata resolution fails or the package selection is invalid.
pub fn get_package_snapshots(
    manifest_path: Option<&Path>,
    workspace_all_members: bool,
    package_filters: &[String],
    all_targets: bool,
    resolution: &ResolutionOptions,
) -> Result<Vec<PackageResult>> {
    fetch_metadata_and_snapshots(
        manifest_path,
        SnapshotMode::Custom {
            workspace_all_members,
            filters: package_filters,
        },
        all_targets,
        resolution,
    )
}

#[derive(Clone, Copy, Debug)]
enum SnapshotMode<'a> {
    RootOnly,
    Custom {
        workspace_all_members: bool,
        filters: &'a [String],
    },
}

fn fetch_metadata_and_snapshots(
    manifest_path: Option<&Path>,
    mode: SnapshotMode<'_>,
    all_targets: bool,
    resolution: &ResolutionOptions,
) -> Result<Vec<PackageResult>> {
    let mut cmd = metadata_command(manifest_path);
    if resolution.all_features {
        cmd.features(CargoOpt::AllFeatures);
    }
    if resolution.no_default_features {
        cmd.features(CargoOpt::NoDefaultFeatures);
    }
    if !resolution.features.is_empty() {
        cmd.features(CargoOpt::SomeFeatures(resolution.features.clone()));
    }
    let mut args = Vec::new();
    if lockfile_path(manifest_path).is_file() {
        args.push("--locked".to_owned());
    }
    if let Some(target) = &resolution.target {
        args.extend(["--filter-platform".to_owned(), target.clone()]);
    }
    cmd.other_options(args);

    let metadata = cmd.exec()?;
    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No dependency resolution found"))?;

    let node_map = build_node_lookup(resolve);
    let pkg_map = build_pkg_lookup(&metadata);

    let workspace_packages_ordered: Vec<&Package> = metadata
        .workspace_members
        .iter()
        .filter_map(|id| metadata.packages.iter().find(|p| &p.id == id))
        .collect();

    let resolve_workspace_root_pkg = || -> Result<&Package> {
        let root_id = resolve
            .root
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No root package in resolve"))?;
        pkg_map
            .get(&root_id.to_string())
            .ok_or_else(|| anyhow::anyhow!("Root package not in cargo metadata packages list"))
    };

    let targets = match mode {
        SnapshotMode::RootOnly => vec![resolve_workspace_root_pkg()?],
        SnapshotMode::Custom {
            workspace_all_members,
            filters,
        } => {
            if workspace_all_members && filters.is_empty() {
                workspace_packages_ordered
            } else if !filters.is_empty() {
                let wanted_set: HashSet<String> = filters
                    .iter()
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect();

                let mut matched: Vec<&Package> = workspace_packages_ordered
                    .iter()
                    .copied()
                    .filter(|p| wanted_set.contains(&p.name.to_ascii_lowercase()))
                    .collect();

                matched.sort_by(|a, b| a.name.cmp(&b.name));

                let mut missing = Vec::new();
                for w in &wanted_set {
                    if !matched
                        .iter()
                        .any(|p| p.name.eq_ignore_ascii_case(w.as_str()))
                    {
                        missing.push(w.clone());
                    }
                }

                if !missing.is_empty() {
                    bail!(
                        "no workspace package(s) matching {missing:?} — available: {}",
                        workspace_packages_ordered
                            .iter()
                            .map(|p| p.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }

                matched
            } else {
                vec![resolve_workspace_root_pkg()?]
            }
        }
    };

    let mut out = Vec::with_capacity(targets.len());
    for pkg in targets {
        let deps = resolve_deps_for_root(&pkg.id, resolve, &pkg_map, &node_map, all_targets)?;
        out.push(PackageResult {
            name: pkg.name.to_string(),
            version: pkg.version.to_string(),
            manifest_path: PathBuf::from(pkg.manifest_path.as_str()),
            deps,
        });
    }

    Ok(out)
}

// Cargo metadata may retain optional edges from the lockfile even when the
// associated feature is disabled (notably weak dependency feature forwarding).
// A strong dependency feature activates its alias; a weak `alias?/feature`
// reference only forwards a feature if the dependency was activated elsewhere.
fn activated_optional_aliases<'a>(package: &'a Package, node: &Node) -> HashSet<&'a str> {
    node.features
        .iter()
        .filter_map(|feature| package.features.get(feature.as_str()))
        .flatten()
        .filter_map(|value| {
            value.strip_prefix("dep:").or_else(|| {
                let (alias, _) = value.split_once('/')?;
                (!alias.ends_with('?')).then_some(alias)
            })
        })
        .collect()
}

fn active_edges<'a>(
    node: &'a Node,
    packages: &HashMap<String, Package>,
) -> Vec<(&'a NodeDep, &'a DepKindInfo)> {
    let parent = packages.get(&node.id.to_string());
    let aliases = parent.map(|package| activated_optional_aliases(package, node));
    node.deps
        .iter()
        .flat_map(|edge| {
            let child = packages.get(&edge.pkg.to_string());
            let aliases = aliases.as_ref();
            edge.dep_kinds
                .iter()
                .filter(move |kind| {
                    let (Some(parent), Some(child), Some(aliases)) = (parent, child, aliases)
                    else {
                        return true;
                    };
                    dependency_kind_active(parent, child, edge, kind, aliases)
                })
                .map(move |kind| (edge, kind))
        })
        .collect()
}

fn dependency_kind_active(
    parent: &Package,
    child: &Package,
    edge: &NodeDep,
    kind: &DepKindInfo,
    aliases: &HashSet<&str>,
) -> bool {
    let mut matched = false;
    for dependency in &parent.dependencies {
        if child.name != dependency.name
            || dependency.kind != kind.kind
            || dependency.target != kind.target
            || !dependency.req.matches(&child.version)
        {
            continue;
        }
        let alias = dependency.rename.as_deref().unwrap_or(&dependency.name);
        let name_matches = alias.replace('-', "_") == edge.name
            || (dependency.rename.is_none()
                && child.targets.iter().any(|target| target.name == edge.name));
        if !name_matches {
            continue;
        }
        matched = true;
        if !dependency.optional || aliases.contains(alias) {
            return true;
        }
    }
    // An edge that cannot be matched to its declaration (e.g. a future Cargo
    // metadata representation) is retained rather than silently losing it.
    !matched
}

/// Resolve flattened dependency list relative to `root_pkg_id`'s subtree.
///
/// When `all_targets` is false (the default), only `[dependencies]` entries are treated as
/// direct. When true, `[dev-dependencies]` and `[build-dependencies]` are also considered direct.
fn resolve_deps_for_root(
    root_pkg_id: &PackageId,
    resolve: &Resolve,
    pkg_map: &HashMap<String, Package>,
    node_map: &HashMap<String, Node>,
    all_targets: bool,
) -> Result<Vec<ResolvedDep>> {
    let root_node = node_map
        .get(&root_pkg_id.to_string())
        .ok_or_else(|| anyhow::anyhow!("Root node missing in resolve.nodes"))?;

    let root_edges = active_edges(root_node, pkg_map);
    let direct_dep_ids: HashSet<String> = root_edges
        .iter()
        .filter(|(_, kind)| all_targets || kind.kind == DependencyKind::Normal)
        .map(|(edge, _)| edge.pkg.to_string())
        .collect();

    let mut reachable = HashSet::new();
    let mut pending: Vec<_> = direct_dep_ids.iter().cloned().collect();
    while let Some(id) = pending.pop() {
        if !reachable.insert(id.clone()) {
            continue;
        }
        if let Some(node) = node_map.get(&id) {
            pending.extend(
                active_edges(node, pkg_map)
                    .into_iter()
                    .filter(|(_, kind)| kind.kind != DependencyKind::Development)
                    .map(|(edge, _)| edge.pkg.to_string()),
            );
        }
    }

    let mut deps = Vec::new();

    for node in &resolve.nodes {
        if node.id == *root_pkg_id || !reachable.contains(&node.id.to_string()) {
            continue;
        }

        let Some(pkg) = pkg_map.get(&node.id.to_string()) else {
            continue;
        };

        let is_direct = direct_dep_ids.contains(&node.id.to_string());

        let enabled_features: Vec<String> = node
            .features
            .iter()
            .map(|s| s.as_str().to_string())
            .collect();

        let available_features: Vec<String> = pkg.features.keys().cloned().collect();

        deps.push(ResolvedDep {
            name: pkg.name.to_string(),
            version: pkg.version.to_string(),
            enabled_features,
            available_features,
            source: pkg.source.as_ref().map(std::string::ToString::to_string),
            repository: pkg.repository.clone(),
            is_direct,
            direct_kinds: root_edges
                .iter()
                .filter(|(edge, kind)| {
                    edge.pkg == node.id && (all_targets || kind.kind == DependencyKind::Normal)
                })
                .map(|(_, kind)| kind.kind)
                .collect(),
        });
    }

    Ok(deps)
}

fn metadata_command(manifest_path: Option<&Path>) -> MetadataCommand {
    let mut cmd = MetadataCommand::new();

    if let Some(path) = manifest_path {
        cmd.manifest_path(path);
    }

    if lockfile_path(manifest_path).is_file() {
        cmd.other_options(vec!["--locked".to_string()]);
    }

    cmd
}

fn lockfile_path(manifest_path: Option<&Path>) -> PathBuf {
    let base = manifest_path
        .and_then(Path::parent)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let absolute = base.canonicalize().unwrap_or_else(|_| base.to_path_buf());
    absolute
        .ancestors()
        .map(|p| p.join("Cargo.lock"))
        .find(|p| p.is_file())
        .unwrap_or_else(|| base.join("Cargo.lock"))
}

#[cfg(test)]
mod optional_edge_tests {
    use super::*;
    use std::fs;

    fn write_package(base: &Path, name: &str, extra: &str) -> Result<()> {
        let path = base.join(name);
        fs::create_dir_all(path.join("src"))?;
        fs::write(path.join("src/lib.rs"), "")?;
        fs::write(
            path.join("Cargo.toml"),
            format!(
                "[package]\nname = {name:?}\nversion = \"0.1.0\"\nedition = \"2024\"\n{extra}\n"
            ),
        )?;
        Ok(())
    }

    #[test]
    fn inactive_optional_edges_do_not_enter_dependency_snapshots() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let base = temp.path();
        for name in [
            "explicit-provider",
            "strong-provider",
            "weak-provider",
            "implicit-provider",
            "root-provider",
            "required-provider",
        ] {
            write_package(base, name, "[features]\nflag = []")?;
        }
        write_package(base, "custom-provider", "[lib]\nname = \"custom_library\"")?;
        write_package(
            base,
            "parent",
            r#"
[dependencies]
explicit-alias = { package = "explicit-provider", path = "../explicit-provider", optional = true }
strong-alias = { package = "strong-provider", path = "../strong-provider", optional = true }
weak-alias = { package = "weak-provider", path = "../weak-provider", optional = true }
implicit-alias = { package = "implicit-provider", path = "../implicit-provider", optional = true }
custom-provider = { path = "../custom-provider", optional = true }
required-provider = { path = "../required-provider" }
[features]
explicit = ["dep:explicit-alias"]
strong = ["strong-alias/flag"]
weak = ["weak-alias?/flag"]
custom = ["dep:custom-provider"]
everything = ["explicit", "strong", "weak", "weak-alias", "implicit-alias", "custom"]
"#,
        )?;
        write_package(
            base,
            "root",
            r#"
[dependencies]
parent = { path = "../parent" }
root-provider = { path = "../root-provider", optional = true }
[features]
everything = ["parent/everything", "dep:root-provider"]
"#,
        )?;
        let mut command = MetadataCommand::new();
        command.manifest_path(base.join("root/Cargo.toml"));
        command.features(CargoOpt::AllFeatures);
        command.other_options(vec!["--offline".into()]);
        let metadata = command.exec()?;
        let packages = build_pkg_lookup(&metadata);
        let mut resolve = metadata
            .resolve
            .ok_or_else(|| anyhow::anyhow!("missing resolve"))?;
        let root = resolve
            .root
            .clone()
            .ok_or_else(|| anyhow::anyhow!("missing root"))?;
        let all = resolve_deps_for_root(
            &root,
            &resolve,
            &packages,
            &build_node_lookup(&resolve),
            false,
        )?;
        assert_eq!(all.len(), 8);
        // Reproduce Cargo retaining edges for inactive weak-forwarded features.
        // Keep the original resolved edge list, but use the actually enabled features.
        for node in &mut resolve.nodes {
            if node.id == root {
                node.features.clear();
            } else if packages
                .get(&node.id.to_string())
                .is_some_and(|package| package.name == "parent")
            {
                node.features.retain(|feature| {
                    matches!(
                        feature.as_str(),
                        "explicit" | "strong" | "strong-alias" | "weak" | "implicit-alias"
                    )
                });
            }
        }
        let active = resolve_deps_for_root(
            &root,
            &resolve,
            &packages,
            &build_node_lookup(&resolve),
            false,
        )?;
        let names: HashSet<_> = active.iter().map(|dep| dep.name.as_str()).collect();
        assert_eq!(
            names,
            HashSet::from([
                "parent",
                "required-provider",
                "explicit-provider",
                "strong-provider",
                "implicit-provider"
            ])
        );
        assert_eq!(active.iter().filter(|dep| dep.is_direct).count(), 1);
        Ok(())
    }
}
