use cargo_anoint::{
    parser::ResolvedDep,
    suggestions::{SuggestionKind, analyze, load_rules},
};
use cargo_metadata::DependencyKind;

fn dependency(name: &str, direct: bool) -> ResolvedDep {
    ResolvedDep {
        name: name.into(),
        version: "1.0.0".into(),
        enabled_features: vec![],
        available_features: vec![],
        source: None,
        repository: None,
        is_direct: direct,
        normal_dependencies: vec![],
        direct_kinds: if direct {
            vec![DependencyKind::Normal]
        } else {
            vec![]
        },
    }
}

#[test]
fn mesh_optimizers_overlap_but_math_and_texture_layers_do_not() {
    let deps = [
        dependency("meshoptimizer-rs", true),
        dependency("rmeshopt", true),
        dependency("glam", true),
        dependency("nalgebra", true),
        dependency("ddsfile", true),
        dependency("bcdec_rs", true),
        dependency("rayon", true),
        dependency("tokio", true),
    ];
    let findings = analyze(None, &deps, &load_rules().unwrap()).unwrap();
    let overlaps: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == SuggestionKind::CapabilityOverlap)
        .collect();
    assert_eq!(overlaps.len(), 1);
    assert_eq!(overlaps[0].current, "meshoptimizer-rs+rmeshopt");
    assert!(!overlaps[0].is_auto_fixable());
}

#[test]
fn graphics_features_and_unmaintained_shaper_are_advisory() {
    let mut wgpu = dependency("wgpu", false);
    wgpu.enabled_features = vec!["default".into()];
    let mut winit = dependency("winit", false);
    winit.enabled_features = vec!["wayland-csd-adwaita".into()];
    let findings = analyze(
        None,
        &[wgpu, winit, dependency("rustybuzz", false)],
        &load_rules().unwrap(),
    )
    .unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.current == "wgpu" && f.kind == SuggestionKind::FeatureOptimization)
    );
    assert!(
        findings
            .iter()
            .any(|f| f.current == "winit" && f.kind == SuggestionKind::FeatureOptimization)
    );
    assert!(
        findings
            .iter()
            .any(|f| f.current == "rustybuzz" && f.kind == SuggestionKind::Unmaintained)
    );
    assert!(findings.iter().all(|f| !f.is_auto_fixable()));
}
