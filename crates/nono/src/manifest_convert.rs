//! Conversion from capability manifest types to internal `CapabilitySet`.
//!
//! This module bridges the schema-generated manifest types with nono's internal
//! enforcement types. `CapabilitySet` is constructed by mapping each manifest
//! domain (filesystem, network, process) to the corresponding builder calls.

#[cfg(target_os = "macos")]
use crate::capability::merge_port_ranges;
use crate::capability::{
    AccessMode as InternalAccessMode, CapabilitySet, IpcMode as InternalIpcMode,
    NetworkMode as InternalNetworkMode, ProcessInfoMode as InternalProcessInfoMode,
    SignalMode as InternalSignalMode,
};
use crate::manifest::{
    AccessMode, CapabilityManifest, FsEntryType, IpcMode, NetworkMode, ProcessInfoMode, Resources,
    SignalMode,
};
use crate::resource::ResourceLimits;
use crate::{NonoError, Result};

impl TryFrom<&CapabilityManifest> for CapabilitySet {
    type Error = NonoError;

    fn try_from(manifest: &CapabilityManifest) -> Result<Self> {
        build_capability_set(manifest)
    }
}

/// Convert a manifest into a `CapabilitySet` together with a D-33
/// enforcement-coverage report for the current host.
///
/// This performs the identical conversion as
/// `TryFrom<&CapabilityManifest>` (it does not change that impl's
/// signature or behavior — see `build_capability_set`, which both share)
/// and additionally reports, per requirement the resulting `CapabilitySet`
/// expresses, whether this host enforces it (`ENFORCED`), could enforce it
/// given a stronger environment (`REQUIRES_STRONGER_ENVIRONMENT`), or
/// cannot enforce it at all (`UNENFORCEABLE`).
///
/// Building the `CapabilitySet` never widens or retries with a weaker
/// manifest based on the report: the report is purely informational at
/// this call site. Callers that must refuse admission on an unenforceable
/// mandatory requirement should call
/// `nono::sandbox::Sandbox::placement_by_coverage(&report)` themselves —
/// that is a deliberate, separate gate, not something this conversion
/// applies implicitly.
///
/// # Errors
///
/// Returns the same errors `TryFrom<&CapabilityManifest>` would (invalid
/// manifest, unsupported resource limits without supervision, etc.).
pub fn capability_set_with_coverage(
    manifest: &CapabilityManifest,
) -> Result<(CapabilitySet, crate::sandbox::EnforcementCoverageReport)> {
    let caps = build_capability_set(manifest)?;
    let report = crate::sandbox::Sandbox::enforcement_coverage(&caps);
    Ok((caps, report))
}

/// Shared conversion body for `TryFrom<&CapabilityManifest>` and
/// `capability_set_with_coverage`. Keep this the single place that maps
/// manifest domains onto `CapabilitySet` builder calls so the two entry
/// points cannot drift apart.
fn build_capability_set(manifest: &CapabilityManifest) -> Result<CapabilitySet> {
    manifest.validate()?;

    let mut caps = CapabilitySet::new();

    // Filesystem grants
    if let Some(ref fs) = manifest.filesystem {
        for grant in &fs.grants {
            let mode = convert_access_mode(grant.access);
            let path = grant.path.as_str();
            caps = match grant.type_ {
                FsEntryType::File => caps.allow_file(path, mode)?,
                FsEntryType::Directory => caps.allow_path(path, mode)?,
            };
        }
        // Note: deny rules are handled at the CLI/profile level, not in CapabilitySet.
        // On Linux/Landlock, deny is expressed by omitting grants (allow-list model).
        // On macOS/Seatbelt, deny rules are injected into the profile by the CLI layer.
    }

    // Network
    if let Some(ref net) = manifest.network {
        caps = match net.mode {
            NetworkMode::Blocked => caps.block_network(),
            // Proxy mode blocks direct network access at the OS level; the CLI
            // layer sets up the reverse proxy separately and allows its port.
            // Port 0 is a placeholder — the CLI fills in the actual proxy port.
            NetworkMode::Proxy => caps.set_network_mode(InternalNetworkMode::ProxyOnly {
                port: 0,
                bind_ports: vec![],
            }),
            NetworkMode::Unrestricted => caps.set_network_mode(InternalNetworkMode::AllowAll),
        };

        // Port allowlists
        if let Some(ref ports) = net.ports {
            for port in &ports.connect {
                let p = u16::try_from(port.get()).map_err(|_| {
                    NonoError::ConfigParse(format!("port {} exceeds u16 range", port))
                })?;
                caps = caps.allow_tcp_connect(p);
            }
            for port in &ports.bind {
                let p = u16::try_from(port.get()).map_err(|_| {
                    NonoError::ConfigParse(format!("port {} exceeds u16 range", port))
                })?;
                caps = caps.allow_tcp_bind(p);
            }
            for port in &ports.localhost {
                let p = u16::try_from(port.get()).map_err(|_| {
                    NonoError::ConfigParse(format!("port {} exceeds u16 range", port))
                })?;
                caps = caps.allow_localhost_port(p);
            }
            let mut raw_ranges: Vec<(u16, u16)> = Vec::new();
            for &[start, end] in &ports.localhost_range {
                let start_u = start.get();
                let end_u = end.get();
                let (start, end) = match (u16::try_from(start_u), u16::try_from(end_u)) {
                    (Ok(s), Ok(e)) => (s, e),
                    _ => {
                        return Err(NonoError::ConfigParse(format!(
                            "localhost_range entry [{start_u}, {end_u}] is invalid: ports must be in 1–65535"
                        )));
                    }
                };
                if start > end {
                    return Err(NonoError::ConfigParse(format!(
                        "localhost_range entry [{start}, {end}] is invalid: start must be <= end"
                    )));
                }
                raw_ranges.push((start, end));
            }
            #[cfg(target_os = "macos")]
            {
                let merged = merge_port_ranges(&raw_ranges);
                let total: u32 = merged
                    .iter()
                    .map(|&(s, e)| (e as u32).saturating_sub(s as u32).saturating_add(1))
                    .fold(0u32, |acc, n| acc.saturating_add(n));
                if total > crate::capability::MACOS_PORT_RANGE_LIMIT {
                    return Err(NonoError::ConfigParse(format!(
                        "localhost_range entries expand to {} unique ports, which exceeds the macOS limit of {} \
                             (sandbox_init crashes above ~17,770 rules); use smaller or fewer ranges",
                        total,
                        crate::capability::MACOS_PORT_RANGE_LIMIT
                    )));
                }
            }
            for (start, end) in raw_ranges {
                caps = caps.allow_localhost_port_range(start, end)?;
            }
        }
    }

    // Process
    if let Some(ref proc) = manifest.process {
        caps = caps.set_signal_mode(convert_signal_mode(proc.signal_mode));
        caps = caps.set_process_info_mode(convert_process_info_mode(proc.process_info_mode));
        caps = caps.set_ipc_mode(convert_ipc_mode(proc.ipc_mode));

        for cmd in &proc.allowed_commands {
            caps = caps.allow_command(cmd.clone());
        }
        for cmd in &proc.blocked_commands {
            caps = caps.block_command(cmd.clone());
        }
    }

    // Resources
    if let Some(ref res) = manifest.resources {
        caps = caps.with_resource_limits(convert_resources(res));
    }

    Ok(caps)
}

fn convert_resources(res: &Resources) -> ResourceLimits {
    ResourceLimits {
        memory_bytes: res.memory_bytes.map(|n| n.get()),
        max_processes: res.max_processes.map(|n| n.get()),
    }
}

fn convert_access_mode(mode: AccessMode) -> InternalAccessMode {
    match mode {
        AccessMode::Read => InternalAccessMode::Read,
        AccessMode::Write => InternalAccessMode::Write,
        AccessMode::Readwrite => InternalAccessMode::ReadWrite,
    }
}

fn convert_signal_mode(mode: SignalMode) -> InternalSignalMode {
    match mode {
        SignalMode::Isolated => InternalSignalMode::Isolated,
        SignalMode::AllowSameSandbox => InternalSignalMode::AllowSameSandbox,
        SignalMode::AllowAll => InternalSignalMode::AllowAll,
    }
}

fn convert_process_info_mode(mode: ProcessInfoMode) -> InternalProcessInfoMode {
    match mode {
        ProcessInfoMode::Isolated => InternalProcessInfoMode::Isolated,
        ProcessInfoMode::AllowSameSandbox => InternalProcessInfoMode::AllowSameSandbox,
        ProcessInfoMode::AllowAll => InternalProcessInfoMode::AllowAll,
    }
}

fn convert_ipc_mode(mode: IpcMode) -> InternalIpcMode {
    match mode {
        IpcMode::SharedMemoryOnly => InternalIpcMode::SharedMemoryOnly,
        IpcMode::Full => InternalIpcMode::Full,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn manifest_resources_map_into_capability_set() {
        let json = r#"{
            "version": "0.1.0",
            "process": { "exec_strategy": "supervised" },
            "resources": { "memory_bytes": 1048576 }
        }"#;
        let manifest = CapabilityManifest::from_json(json).unwrap();
        let caps = CapabilitySet::try_from(&manifest).unwrap();
        let limits = caps.resource_limits().expect("limits present");
        assert_eq!(limits.memory_bytes, Some(1048576));
    }

    #[test]
    fn manifest_without_resources_has_no_limits() {
        let json = r#"{ "version": "0.1.0" }"#;
        let manifest = CapabilityManifest::from_json(json).unwrap();
        let caps = CapabilitySet::try_from(&manifest).unwrap();
        assert!(caps.resource_limits().is_none());
    }

    #[test]
    fn manifest_max_processes_maps_into_capability_set() {
        // The process-count ceiling flows the same path as memory: schema
        // (NonZeroU64) -> convert_resources -> ResourceLimits.max_processes.
        let json = r#"{
            "version": "0.1.0",
            "process": { "exec_strategy": "supervised" },
            "resources": { "max_processes": 64 }
        }"#;
        let manifest = CapabilityManifest::from_json(json).unwrap();
        let caps = CapabilitySet::try_from(&manifest).unwrap();
        let limits = caps.resource_limits().expect("limits present");
        assert_eq!(limits.max_processes, Some(64));
        // A process-only manifest leaves memory unset.
        assert_eq!(limits.memory_bytes, None);
    }

    #[test]
    fn manifest_both_ceilings_map_together() {
        let json = r#"{
            "version": "0.1.0",
            "process": { "exec_strategy": "supervised" },
            "resources": { "memory_bytes": 1048576, "max_processes": 32 }
        }"#;
        let manifest = CapabilityManifest::from_json(json).unwrap();
        let caps = CapabilitySet::try_from(&manifest).unwrap();
        let limits = caps.resource_limits().expect("limits present");
        assert_eq!(limits.memory_bytes, Some(1048576));
        assert_eq!(limits.max_processes, Some(32));
    }

    #[test]
    fn try_from_rejects_unsupervised_max_processes() {
        // Mirror of try_from_runs_validate_and_rejects_unsupervised_memory for the
        // process-count ceiling: it too is enforced by the supervising parent, so an
        // unsupervised manifest must be rejected rather than build an unenforceable set.
        let json = r#"{ "version": "0.1.0", "resources": { "max_processes": 8 } }"#;
        let manifest = CapabilityManifest::from_json(json).unwrap();
        let err = CapabilitySet::try_from(&manifest)
            .expect_err("unsupervised max_processes limit must be rejected by TryFrom");
        assert!(matches!(err, NonoError::ConfigParse(_)), "got {err:?}");
    }

    // ---- TryFrom enforces validate(); empty resources maps clean ----

    #[test]
    fn try_from_runs_validate_and_rejects_unsupervised_memory() {
        // CapabilitySet::try_from(&manifest) calls manifest.validate() first, so a
        // memory ceiling under the default (monitor) strategy must surface the same
        // ConfigParse rather than silently building an unenforceable set.
        let json = r#"{ "version": "0.1.0", "resources": { "memory_bytes": 1024 } }"#;
        let manifest = CapabilityManifest::from_json(json).unwrap();
        let err = CapabilitySet::try_from(&manifest)
            .expect_err("unsupervised memory limit must be rejected by TryFrom");
        assert!(matches!(err, NonoError::ConfigParse(_)), "got {err:?}");
    }

    #[test]
    fn empty_resources_object_maps_to_no_ceiling() {
        // `resources: {}` is present-but-empty: the conversion still attaches a
        // ResourceLimits, but it must carry no ceiling (is_empty), never a phantom
        // limit. Distinct from manifest_without_resources_has_no_limits, which omits
        // the resources key entirely.
        let json = r#"{ "version": "0.1.0", "resources": {} }"#;
        let manifest = CapabilityManifest::from_json(json).unwrap();
        let caps = CapabilitySet::try_from(&manifest).unwrap();
        // The conversion must attach a ResourceLimits (assert Some first, so this
        // can't pass vacuously if conversion ever returned None for `{}`)...
        let limits = caps
            .resource_limits()
            .expect("empty resources must still attach a ResourceLimits");
        // ...and that ResourceLimits must carry no ceiling, never a phantom limit.
        assert!(
            limits.is_empty(),
            "empty resources must not produce a ceiling, got {limits:?}"
        );
    }

    // ---- capability_set_with_coverage (NONO-COV-001 / D-33) ----

    #[test]
    fn with_coverage_builds_the_same_capability_set_as_try_from() {
        // The coverage-producing entry point must not diverge from
        // `TryFrom<&CapabilityManifest>`: same manifest in, same
        // `CapabilitySet` out (compared field-by-field — `CapabilitySet`
        // has no `PartialEq`), on top of the identical `build_capability_set`
        // used by both.
        let dir = tempfile::tempdir().unwrap();
        let json = format!(
            r#"{{
                "version": "0.1.0",
                "filesystem": {{ "grants": [
                    {{ "path": {:?}, "type": "directory", "access": "read" }}
                ] }},
                "network": {{ "mode": "blocked" }},
                "process": {{ "exec_strategy": "monitor", "signal_mode": "isolated" }}
            }}"#,
            dir.path().to_str().unwrap()
        );
        let manifest = CapabilityManifest::from_json(&json).unwrap();

        let via_try_from = CapabilitySet::try_from(&manifest).unwrap();
        let (via_coverage, report) = capability_set_with_coverage(&manifest).unwrap();

        assert_eq!(
            via_try_from.fs_capabilities().len(),
            via_coverage.fs_capabilities().len()
        );
        for (a, b) in via_try_from
            .fs_capabilities()
            .iter()
            .zip(via_coverage.fs_capabilities())
        {
            assert_eq!(a.resolved, b.resolved);
            assert_eq!(a.access, b.access);
            assert_eq!(a.is_file, b.is_file);
        }
        assert_eq!(via_try_from.network_mode(), via_coverage.network_mode());
        assert_eq!(via_try_from.signal_mode(), via_coverage.signal_mode());

        // And a coverage report was actually produced alongside it — one
        // requirement per domain the manifest expressed (filesystem,
        // network; `signal_mode: "isolated"` is the schema default and is
        // still a reportable requirement, see `SignalMode::Isolated`'s own
        // best-effort doc comment).
        assert!(
            !report.requirements.is_empty(),
            "a manifest with explicit filesystem/network/process domains must yield a non-empty coverage report"
        );
    }

    #[test]
    fn with_coverage_rejects_the_same_manifests_try_from_rejects() {
        // `build_capability_set` is the single shared body: an invalid
        // manifest must fail identically through either entry point.
        let json = r#"{ "version": "0.1.0", "resources": { "memory_bytes": 1024 } }"#;
        let manifest = CapabilityManifest::from_json(json).unwrap();

        let try_from_err = CapabilitySet::try_from(&manifest).expect_err("TryFrom must reject");
        let coverage_err =
            capability_set_with_coverage(&manifest).expect_err("with_coverage must reject too");

        assert!(matches!(try_from_err, NonoError::ConfigParse(_)));
        assert!(matches!(coverage_err, NonoError::ConfigParse(_)));
    }

    #[test]
    fn with_coverage_attaches_a_report_the_placement_rule_can_gate_on() {
        // End-to-end wiring for NONO-COV-001's stated deliverable: nono's
        // own manifest-to-sandbox path produces a coverage report a caller
        // can hand to `Sandbox::placement_by_coverage` to decide admission,
        // without this conversion applying that decision itself.
        let json = r#"{
            "version": "0.1.0",
            "process": { "exec_strategy": "monitor", "signal_mode": "allow_same_sandbox" }
        }"#;
        let manifest = CapabilityManifest::from_json(json).unwrap();
        let (_caps, report) = capability_set_with_coverage(&manifest).unwrap();

        let signal = report
            .requirements
            .iter()
            .find(|r| r.domain == crate::sandbox::CoverageDomain::Signal)
            .expect("signal_mode: allow_same_sandbox must produce a Signal requirement");
        assert!(
            signal.mandatory,
            "AllowSameSandbox is mandatory: nono already fails closed on it elsewhere"
        );

        // The gate is a separate, explicit step — never applied implicitly
        // by the conversion itself.
        let _ = crate::sandbox::Sandbox::placement_by_coverage(&report);
    }
}
