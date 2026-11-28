//! Parser layer — extracts the full dependency tree from Cargo.toml / Cargo.lock
//! using `cargo_metadata` for feature-aware resolution.

use anyhow::{Context, Result, bail};
use cargo_metadata::semver::Version;
use cargo_metadata::{
    CargoOpt, DepKindInfo, DependencyKind, MetadataCommand, Node, NodeDep, Package, PackageId,
    Resolve,
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
    /// For direct packages, names of active, immediate normal dependencies.
    pub normal_dependencies: Vec<String>,
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
    packages: &HashMap<&PackageId, &Package>,
) -> Vec<(&'a NodeDep, &'a DepKindInfo)> {
    let parent = packages.get(&node.id);
    let aliases = parent.map(|package| activated_optional_aliases(package, node));
    node.deps
        .iter()
        .flat_map(|edge| {
            let child = packages.get(&edge.pkg);
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
        if dependency.name != child.name
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
    pkg_map: &HashMap<&PackageId, &Package>,
    node_map: &HashMap<&PackageId, &Node>,
    all_targets: bool,
) -> Result<Vec<ResolvedDep>> {
    let root_node = node_map
        .get(root_pkg_id)
        .ok_or_else(|| anyhow::anyhow!("Root node missing in resolve.nodes"))?;

    let mut direct_roles: HashMap<&PackageId, Vec<DependencyKind>> = HashMap::new();
    for (edge, kind) in active_edges(root_node, pkg_map) {
        if all_targets || kind.kind == DependencyKind::Normal {
            let roles = direct_roles.entry(&edge.pkg).or_default();
            if !roles.contains(&kind.kind) {
                roles.push(kind.kind);
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
            active_edges(node, pkg_map)
                .into_iter()
                .filter(|(_, kind)| kind.kind != DependencyKind::Development)
                .map(|(edge, _)| &edge.pkg),
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
            normal_dependencies: if direct_roles.contains_key(&node.id) {
                active_edges(node, pkg_map)
                    .into_iter()
                    .filter(|(_, kind)| kind.kind == DependencyKind::Normal)
                    .map(|(edge, _)| {
                        pkg_map
                            .get(&edge.pkg)
                            .map(|child| child.name.clone())
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "Resolved package {} missing from metadata",
                                    edge.pkg
                                )
                            })
                    })
                    .collect::<Result<BTreeSet<_>>>()?
                    .into_iter()
                    .collect()
            } else {
                Vec::new()
            },
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
            .clone()
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
                .get(&node.id)
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
        assert_eq!(active.iter().filter(|dep| dep.is_direct()).count(), 1);
        let parent = active
            .iter()
            .find(|dep| dep.name == "parent")
            .ok_or_else(|| anyhow::anyhow!("missing parent"))?;
        assert_eq!(
            parent
                .normal_dependencies
                .iter()
                .map(String::as_str)
                .collect::<HashSet<_>>(),
            HashSet::from([
                "required-provider",
                "explicit-provider",
                "strong-provider",
                "implicit-provider"
            ])
        );
        assert!(
            active
                .iter()
                .filter(|dep| !dep.is_direct())
                .all(|dep| dep.normal_dependencies.is_empty())
        );
        Ok(())
    }
}
