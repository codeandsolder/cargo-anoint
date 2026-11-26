//! Parser layer — extracts the full dependency tree from Cargo.toml / Cargo.lock
//! using `cargo_metadata` for feature-aware resolution.

use anyhow::{Context, Result, bail};
use cargo_metadata::semver::Version;
use cargo_metadata::{
    CargoOpt, DependencyKind, MetadataCommand, Node, Package, PackageId, Resolve,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};

/// A resolved dependency with its name, version, and enabled features.
#[derive(Debug, Clone)]
pub struct ResolvedDep {
    pub name: String,
    pub version: Version,
    /// Features that are **actually enabled** in the resolved build plan.
    pub enabled_features: Vec<String>,
    /// All features **declared** by the crate (available but not necessarily enabled).
    pub available_features: Vec<String>,
    pub source: Option<String>,
    pub repository: Option<String>,
    pub direct_kinds: Vec<DependencyKind>,
}

impl ResolvedDep {
    /// Whether the selected package declares this dependency in an included role.
    #[must_use = "Distinguishes direct and transitive dependencies"]
    pub const fn is_direct(&self) -> bool {
        !self.direct_kinds.is_empty()
    }
    /// Whether the resolved package comes from the crates.io registry.
    #[must_use = "Registry identity determines whether crates.io metadata applies"]
    pub fn is_crates_io(&self) -> bool {
        matches!(
            self.source.as_deref(),
            Some(
                "registry+https://github.com/rust-lang/crates.io-index"
                    | "sparse+https://index.crates.io/"
            )
        )
    }
}

/// One Cargo package in the workspace (or the resolved root crate) plus its dependency tree.
///
/// Produced before suggestion analysis runs.
#[derive(Debug, Clone)]
pub struct PackageResult {
    pub name: String,
    pub version: Version,
    pub manifest_path: PathBuf,
    pub deps: Vec<ResolvedDep>,
}

impl fmt::Display for ResolvedDep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag = if self.is_direct() {
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

/// Build a lookup from package ID to the resolved Node (which carries enabled features).
fn build_node_lookup(resolve: &Resolve) -> HashMap<&PackageId, &Node> {
    resolve.nodes.iter().map(|n| (&n.id, n)).collect()
}

/// Build a map from package ID to package reference.
fn build_pkg_lookup(metadata: &cargo_metadata::Metadata) -> HashMap<&PackageId, &Package> {
    metadata.packages.iter().map(|p| (&p.id, p)).collect()
}

/// Feature and platform options for Cargo dependency resolution.
#[derive(Debug, Default)]
pub struct ResolutionOptions {
    pub all_features: bool,
    pub features: Vec<String>,
    pub no_default_features: bool,
    pub target: Option<String>,
}

/// Which workspace packages to analyze.
#[derive(Clone, Copy, Debug)]
pub enum PackageSelection<'a> {
    /// Only the package at the selected manifest.
    Root,
    /// Every member of the workspace.
    All,
    /// Exact package names. Empty selections are invalid.
    Names(&'a [String]),
}

/// Resolve Cargo dependency snapshots for the selected packages.
///
/// With `all_targets`, direct dependencies include development and build dependencies.
/// # Errors
/// Returns an error if metadata resolution fails or the package selection is invalid.
pub fn get_package_snapshots(
    manifest_path: Option<&Path>,
    selection: PackageSelection<'_>,
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
    // Only the actual workspace lockfile matters. An unrelated ancestor
    // package can have a Cargo.lock without owning this package.
    let layout = metadata_command(manifest_path)
        .no_deps()
        .exec()
        .context("discover Cargo workspace root")?;
    if layout
        .workspace_root
        .join("Cargo.lock")
        .as_std_path()
        .try_exists()?
    {
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

    let targets = select_packages(&metadata, resolve, &pkg_map, selection)?;

    let mut out = Vec::with_capacity(targets.len());
    for pkg in targets {
        let deps = resolve_deps_for_root(&pkg.id, resolve, &pkg_map, &node_map, all_targets)?;
        out.push(PackageResult {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            manifest_path: PathBuf::from(pkg.manifest_path.as_str()),
            deps,
        });
    }

    Ok(out)
}

fn select_packages<'a>(
    metadata: &'a cargo_metadata::Metadata,
    resolve: &Resolve,
    pkg_map: &HashMap<&PackageId, &'a Package>,
    selection: PackageSelection<'_>,
) -> Result<Vec<&'a Package>> {
    let workspace_packages_ordered: Vec<&Package> = metadata
        .workspace_members
        .iter()
        .map(|id| {
            pkg_map
                .get(id)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("Workspace member {id} missing from metadata"))
        })
        .collect::<Result<_>>()?;

    let resolve_workspace_root_pkg = || -> Result<&Package> {
        let root_id = resolve
            .root
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No root package in resolve"))?;
        pkg_map
            .get(root_id)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("Root package not in cargo metadata packages list"))
    };

    match selection {
        PackageSelection::Root => Ok(vec![resolve_workspace_root_pkg()?]),
        PackageSelection::All => Ok(workspace_packages_ordered),
        PackageSelection::Names(names) => {
            anyhow::ensure!(
                !names.is_empty(),
                "workspace package selection must not be empty"
            );
            filter_workspace_members(&workspace_packages_ordered, names)
        }
    }
}

fn filter_workspace_members<'a>(
    workspace: &[&'a Package],
    filters: &[String],
) -> Result<Vec<&'a Package>> {
    let mut missing: BTreeSet<&str> = filters.iter().map(|name| name.trim()).collect();
    anyhow::ensure!(
        !missing.contains(""),
        "workspace package names must not be empty"
    );
    let mut matched: Vec<_> = workspace
        .iter()
        .copied()
        .filter(|package| missing.remove(package.name.as_str()))
        .collect();
    if !missing.is_empty() {
        bail!(
            "no workspace package(s) matching {missing:?} — available: {}",
            workspace
                .iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    matched.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    Ok(matched)
}

/// Resolve flattened dependency list relative to `root_pkg_id`'s subtree.
///
/// When `all_targets` is false (the default), only `[dependencies]` entries are treated as
/// direct. When true, `[dev-dependencies]` and `[build-dependencies]` are also considered direct.
fn resolve_deps_for_root(
    root_pkg_id: &PackageId,
    resolve: &Resolve,
    pkg_map: &HashMap<&PackageId, &Package>,
    node_map: &HashMap<&PackageId, &Node>,
    all_targets: bool,
) -> Result<Vec<ResolvedDep>> {
    let root_node = node_map
        .get(root_pkg_id)
        .ok_or_else(|| anyhow::anyhow!("Root node missing in resolve.nodes"))?;

    let mut direct_roles: HashMap<&PackageId, Vec<DependencyKind>> = HashMap::new();
    for edge in &root_node.deps {
        for kind in edge.dep_kinds.iter().map(|kind| kind.kind) {
            if all_targets || kind == DependencyKind::Normal {
                let roles = direct_roles.entry(&edge.pkg).or_default();
                if !roles.contains(&kind) {
                    roles.push(kind);
                }
            }
        }
    }

    let mut reachable = HashSet::new();
    let mut pending: Vec<_> = direct_roles.keys().copied().collect();
    while let Some(id) = pending.pop() {
        if !reachable.insert(id) {
            continue;
        }
        let node = node_map
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("Reachable dependency {id} missing from resolution"))?;
        pending.extend(
            node.deps
                .iter()
                .filter(|d| {
                    d.dep_kinds
                        .iter()
                        .any(|k| k.kind != DependencyKind::Development)
                })
                .map(|d| &d.pkg),
        );
    }

    let mut deps = Vec::new();

    for node in &resolve.nodes {
        if node.id == *root_pkg_id || !reachable.contains(&node.id) {
            continue;
        }

        let pkg = pkg_map
            .get(&node.id)
            .ok_or_else(|| anyhow::anyhow!("Resolved package {} missing from metadata", node.id))?;

        let enabled_features = node.features.clone();

        let available_features: Vec<String> = pkg.features.keys().cloned().collect();

        deps.push(ResolvedDep {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            enabled_features,
            available_features,
            source: pkg.source.as_ref().map(std::string::ToString::to_string),
            repository: pkg.repository.clone(),
            direct_kinds: direct_roles.remove(&node.id).unwrap_or_default(),
        });
    }

    Ok(deps)
}

fn metadata_command(manifest_path: Option<&Path>) -> MetadataCommand {
    let mut cmd = MetadataCommand::new();

    if let Some(path) = manifest_path {
        cmd.manifest_path(path);
    }

    cmd
}
