//! Parser layer — extracts the full dependency tree from Cargo.toml / Cargo.lock
//! using `cargo_metadata` for feature-aware resolution.

use anyhow::{Result, bail};
use cargo_metadata::{
    CargoOpt, DependencyKind, MetadataCommand, Node, Package, PackageId, Resolve,
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
    pub direct_kinds: Vec<DependencyKind>,
}

impl ResolvedDep {
    /// Whether the selected package declares this dependency in an included role.
    #[must_use = "Distinguishes direct and transitive dependencies"]
    pub const fn is_direct(&self) -> bool {
        !self.direct_kinds.is_empty()
    }
}

/// One Cargo package in the workspace (or the resolved root crate) plus its dependency tree.
///
/// Produced before suggestion analysis runs.
#[derive(Debug, Clone)]
pub struct PackageResult {
    pub name: String,
    pub version: String,
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

    let targets = select_packages(&metadata, resolve, &pkg_map, mode)?;

    let mut out = Vec::with_capacity(targets.len());
    for pkg in targets {
        let deps = resolve_deps_for_root(&pkg.id, resolve, &pkg_map, &node_map, all_targets)?;
        out.push(PackageResult {
            name: pkg.name.clone(),
            version: pkg.version.to_string(),
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
    mode: SnapshotMode<'_>,
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
                        missing.push(w);
                    }
                }

                if !missing.is_empty() {
                    missing.sort_unstable();
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
    Ok(targets)
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
            version: pkg.version.to_string(),
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
