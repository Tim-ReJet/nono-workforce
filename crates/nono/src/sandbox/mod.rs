//! OS-level sandbox implementation
//!
//! This module provides the core sandboxing functionality using platform-specific
//! mechanisms:
//! - Linux: Landlock LSM
//! - macOS: Seatbelt sandbox

use crate::capability::CapabilitySet;
use crate::error::{NonoError, Result};

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

// Re-export macOS extension functions for supervisor use
#[cfg(target_os = "macos")]
pub use macos::{extension_consume, extension_issue_file, extension_release};

// Re-export Linux Landlock ABI detection and scope policy reporting
#[cfg(target_os = "linux")]
pub use linux::{
    DetectedAbi, LandlockScopePolicy, detect_abi, landlock_scope_policy, restrict_execute,
};

// Re-export Linux WSL2 detection
#[cfg(target_os = "linux")]
pub use linux::is_wsl2;

// Re-export Linux seccomp-notify primitives for supervisor use
#[cfg(target_os = "linux")]
pub use linux::{
    OpenHow, PreparedLandlockSandbox, PreparedSeccompNotifyFilter, RawSandboxError,
    RawSandboxStage, SYS_BIND, SYS_CONNECT, SYS_OPENAT, SYS_OPENAT2, SYS_SENDMMSG, SYS_SENDMSG,
    SYS_SENDTO, SeccompData, SeccompNetFallback, SeccompNotif, SeccompOpts, SockaddrInfo,
    UnixSocketKind, classify_access_from_flags, classify_af_unix, continue_notif, deny_notif,
    inject_fd, install_seccomp_af_unix_filter, install_seccomp_notify,
    install_seccomp_proxy_filter, notif_id_valid, prepare_seccomp_af_unix_filter,
    prepare_seccomp_proxy_filter, prepare_seccomp_with_abi, probe_seccomp_block_network_support,
    read_mmsghdr_dests, read_msghdr_dest, read_notif_path, read_notif_sockaddr, read_open_how,
    recv_notif, resolve_notif_path, respond_notif_errno, validate_openat2_size,
};

/// Information about sandbox support on this platform
#[derive(Debug, Clone)]
pub struct SupportInfo {
    /// Whether sandboxing is supported
    pub is_supported: bool,
    /// Platform name
    pub platform: &'static str,
    /// Detailed support information
    pub details: String,
}

/// Main sandbox API
///
/// This struct provides static methods for applying sandboxing restrictions.
/// Once applied, restrictions cannot be removed or expanded.
///
/// # Example
///
/// ```no_run
/// use nono::{CapabilitySet, AccessMode, Sandbox};
///
/// let caps = CapabilitySet::new()
///     .allow_path("/usr", AccessMode::Read)?
///     .allow_path("/project", AccessMode::ReadWrite)?
///     .block_network();
///
/// // Check if sandbox is supported
/// if Sandbox::is_supported() {
///     Sandbox::apply_auto(&caps)?;
/// }
/// # Ok::<(), nono::NonoError>(())
/// ```
pub struct Sandbox;

impl Sandbox {
    /// Detect the Landlock ABI version supported by the running kernel.
    ///
    /// This is only available on Linux. Returns a `DetectedAbi` that can
    /// be passed to `apply_with_abi()` to avoid re-probing.
    ///
    /// # Errors
    ///
    /// Returns an error if Landlock is not available.
    #[cfg(target_os = "linux")]
    #[must_use = "ABI detection result should be checked"]
    pub fn detect_abi() -> Result<DetectedAbi> {
        linux::detect_abi()
    }

    /// Apply sandboxing with automatic Landlock → seccomp fallback (Linux).
    ///
    /// Uses Landlock where possible; falls back to seccomp when the kernel
    /// ABI lacks network support (< V4). This preserves the compatibility
    /// behaviour for library consumers; the CLI selects
    /// [`SeccompOpts::network_baseline`] for its stronger default.
    /// `BlockAll` is installed inline; `ProxyOnly` must be installed
    /// post-fork via `install_seccomp_proxy_filter()`.
    #[cfg(target_os = "linux")]
    #[must_use = "sandbox application result should be checked"]
    pub fn apply_auto(caps: &CapabilitySet) -> Result<linux::SeccompNetFallback> {
        linux::apply_auto(caps)
    }

    /// Apply sandboxing with automatic fallback and a pre-detected ABI (Linux).
    #[cfg(target_os = "linux")]
    #[must_use = "sandbox application result should be checked"]
    pub fn apply_auto_with_abi(
        caps: &CapabilitySet,
        abi: &DetectedAbi,
    ) -> Result<linux::SeccompNetFallback> {
        linux::apply_auto_with_abi(caps, abi)
    }

    /// Apply Landlock-only sandboxing (Linux).
    ///
    /// Returns an error if network restrictions cannot be satisfied via
    /// Landlock alone (kernel ABI < V4). Use `apply_auto` for fallback.
    #[cfg(target_os = "linux")]
    pub fn apply_landlock(caps: &CapabilitySet) -> Result<()> {
        linux::apply_landlock(caps)
    }

    /// Apply Landlock-only sandboxing with a pre-detected ABI (Linux).
    #[cfg(target_os = "linux")]
    pub fn apply_landlock_with_abi(caps: &CapabilitySet, abi: &DetectedAbi) -> Result<()> {
        linux::apply_landlock_with_abi(caps, abi)
    }

    /// Apply Landlock filesystem/process sandboxing and seccomp TCP fallback (Linux).
    ///
    /// Filesystem/process sandboxing is always Landlock-enforced. `opts`
    /// controls only nono-managed TCP network fallback/delegation.
    #[cfg(target_os = "linux")]
    pub fn apply_seccomp(
        caps: &CapabilitySet,
        opts: linux::SeccompOpts,
    ) -> Result<linux::SeccompNetFallback> {
        linux::apply_seccomp(caps, opts)
    }

    /// Apply Landlock filesystem/process sandboxing and seccomp TCP fallback
    /// with a pre-detected ABI (Linux).
    #[cfg(target_os = "linux")]
    pub fn apply_seccomp_with_abi(
        caps: &CapabilitySet,
        abi: &DetectedAbi,
        opts: linux::SeccompOpts,
    ) -> Result<linux::SeccompNetFallback> {
        linux::apply_seccomp_with_abi(caps, abi, opts)
    }

    /// Prepare an allocation-free Linux sandbox apply for a raw-cloned child.
    #[cfg(target_os = "linux")]
    pub fn prepare_seccomp_with_abi(
        caps: &CapabilitySet,
        abi: &DetectedAbi,
        opts: linux::SeccompOpts,
    ) -> Result<linux::PreparedLandlockSandbox> {
        linux::prepare_seccomp_with_abi(caps, abi, opts)
    }

    /// Declare that TCP network enforcement is handled externally (Linux).
    ///
    /// This is intentionally a no-op marker. It must not be used as the whole
    /// `nono run` sandbox; filesystem/process sandboxing is applied separately.
    #[cfg(target_os = "linux")]
    pub fn apply_external() -> Result<()> {
        linux::apply_external()
    }

    /// Apply the sandbox with the given capabilities (macOS).
    #[cfg(target_os = "macos")]
    #[must_use = "sandbox application result should be checked"]
    pub fn apply_auto(caps: &CapabilitySet) -> Result<()> {
        macos::apply(caps)
    }

    /// Stack a second Landlock layer that restricts execute to the given paths (Linux only).
    ///
    /// Must be called after `apply()`. See [`linux::restrict_execute`] for semantics.
    ///
    /// # Errors
    ///
    /// Returns an error if the restriction cannot be applied.
    #[cfg(target_os = "linux")]
    pub fn restrict_execute(paths: &[impl AsRef<std::path::Path>]) -> Result<()> {
        linux::restrict_execute(paths)
    }

    /// Check if sandboxing is supported on this platform
    #[must_use]
    pub fn is_supported() -> bool {
        #[cfg(target_os = "linux")]
        {
            linux::is_supported()
        }

        #[cfg(target_os = "macos")]
        {
            macos::is_supported()
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            false
        }
    }

    /// Get detailed information about sandbox support on this platform
    #[must_use]
    pub fn support_info() -> SupportInfo {
        #[cfg(target_os = "linux")]
        {
            linux::support_info()
        }

        #[cfg(target_os = "macos")]
        {
            macos::support_info()
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            SupportInfo {
                is_supported: false,
                platform: std::env::consts::OS,
                details: format!("Platform '{}' is not supported", std::env::consts::OS),
            }
        }
    }

    /// Report per-requirement enforcement coverage for `caps` on the
    /// current host (D-33).
    ///
    /// For each requirement derived from the capability set (filesystem
    /// grants, network mode, signal isolation, abstract UNIX socket
    /// scoping), reports the component that would enforce it, the applied
    /// configuration/version, observed evidence, and a tri-state result:
    /// `Enforced`, `RequiresStrongerEnvironment`, or `Unenforceable`.
    ///
    /// This generalizes the requested/enforced pair already reported by
    /// `LandlockScopePolicy` (Linux signal/abstract-socket scoping) to
    /// every domain a `CapabilitySet` can express, on every supported
    /// platform.
    ///
    /// This never fails: a host that cannot enforce something still gets a
    /// report saying so (`Unenforceable`), rather than an error the caller
    /// could discard. Use [`Sandbox::placement_by_coverage`] to turn the
    /// report into a blocking decision.
    #[must_use]
    pub fn enforcement_coverage(caps: &CapabilitySet) -> EnforcementCoverageReport {
        #[cfg(target_os = "linux")]
        {
            linux_enforcement_coverage(caps)
        }

        #[cfg(target_os = "macos")]
        {
            macos_enforcement_coverage(caps)
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            unsupported_enforcement_coverage(caps)
        }
    }

    /// D-33 placement rule: refuse admission if any *mandatory* requirement
    /// in `report` resolved `Unenforceable`.
    ///
    /// This is a gate only. It has no authority to relax, retry, or widen
    /// the requirement it reports on — it either returns `Ok(())` because
    /// every mandatory requirement is covered, or it returns an error
    /// naming the first one that is not. Requirements nono's own capability
    /// types already document as best-effort (e.g. `SignalMode::Isolated`,
    /// `IpcMode::SharedMemoryOnly` degrading below Landlock V6) are not
    /// mandatory and do not block here, matching the behavior those types
    /// already document; only requirements whose failure to enforce is
    /// already a hard stop elsewhere (e.g. `SignalMode::AllowSameSandbox`
    /// below V6, or no sandbox backend at all) can block.
    ///
    /// # Errors
    ///
    /// Returns [`NonoError::SandboxInit`] naming the first blocking
    /// requirement when `report.unenforceable_mandatory()` is non-empty.
    pub fn placement_by_coverage(report: &EnforcementCoverageReport) -> Result<()> {
        if let Some(blocking) = report.unenforceable_mandatory().first() {
            return Err(NonoError::SandboxInit(format!(
                "mandatory requirement '{}' is unenforceable on this host ({}); \
                 refusing admission per D-33 rather than degrading silently",
                blocking.requirement, blocking.evidence
            )));
        }
        Ok(())
    }
}

/// Tri-state result of an enforcement-coverage check for one requirement
/// (D-33). `Enforced` is the only passing result — `RequiresStrongerEnvironment`
/// and `Unenforceable` are both "not a pass"; callers must never treat
/// either as success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageResult {
    /// Enforced by the current host as configured.
    Enforced,
    /// Not enforced by this host today; a stronger environment (a newer
    /// kernel ABI, a different sandbox backend) could enforce it. Reported
    /// for visibility (e.g. Cell RuntimeClass placement); does not by
    /// itself block nono admission unless the requirement is mandatory
    /// and a stronger environment is unavailable — see
    /// [`Sandbox::placement_by_coverage`].
    RequiresStrongerEnvironment,
    /// Not enforceable by any component this build knows how to apply.
    Unenforceable,
}

impl CoverageResult {
    /// The only value that represents a genuine pass.
    #[must_use]
    pub fn is_enforced(self) -> bool {
        matches!(self, CoverageResult::Enforced)
    }
}

/// The domain a [`RequirementCoverage`] entry was derived from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageDomain {
    /// A filesystem grant (`CapabilitySet::fs_capabilities()`).
    Filesystem,
    /// The network mode (`CapabilitySet::network_mode()`).
    Network,
    /// Signal isolation (`CapabilitySet::signal_mode()`).
    Signal,
    /// Abstract UNIX socket scoping, driven by IPC mode
    /// (`CapabilitySet::ipc_mode()`). Linux-only concept: macOS has no
    /// abstract-socket namespace, so this domain produces no requirement
    /// there.
    AbstractUnixSocket,
}

/// Enforcement coverage for one requirement derived from a `CapabilitySet`:
/// which component would enforce it, at what applied configuration, what
/// was observed, whether the requirement is mandatory, and the tri-state
/// result (D-33).
#[derive(Debug, Clone)]
pub struct RequirementCoverage {
    /// Stable identifier for the requirement, e.g.
    /// `"filesystem:/project (read+write)"` or `"network:Blocked"`.
    pub requirement: String,
    /// The domain this requirement was derived from.
    pub domain: CoverageDomain,
    /// The component that would enforce this requirement (e.g.
    /// `"landlock"`, `"seatbelt"`, `"none"`).
    pub enforcing_component: &'static str,
    /// The applied configuration/version the enforcing component was
    /// evaluated at (e.g. `"V4"`, `"V1"`, or a macOS support-info string).
    pub applied_configuration: String,
    /// Human-readable observed evidence backing `result`.
    pub evidence: String,
    /// Whether an `Unenforceable` result for this requirement blocks
    /// admission via [`Sandbox::placement_by_coverage`].
    ///
    /// The manifest schema has no optional/waiver field, so this mirrors —
    /// rather than invents — the mandatory/best-effort distinction nono's
    /// capability types already document: `false` only for the specific
    /// cases those docs already call best-effort (`SignalMode::Isolated`,
    /// `IpcMode::SharedMemoryOnly`); `true` everywhere else, including the
    /// one case (`SignalMode::AllowSameSandbox` without scope support)
    /// that already hard-fails elsewhere in nono today.
    pub mandatory: bool,
    /// The tri-state enforcement result.
    pub result: CoverageResult,
}

/// Per-requirement enforcement coverage for a `CapabilitySet` on the
/// current host (D-33). Always produced, even when the host cannot enforce
/// anything: a coverage report that fails to build would itself be the
/// kind of silent degradation D-33 exists to prevent.
#[derive(Debug, Clone, Default)]
pub struct EnforcementCoverageReport {
    /// One entry per requirement examined.
    pub requirements: Vec<RequirementCoverage>,
}

impl EnforcementCoverageReport {
    /// Mandatory requirements that resolved `Unenforceable`. Non-empty
    /// means [`Sandbox::placement_by_coverage`] will refuse admission.
    #[must_use]
    pub fn unenforceable_mandatory(&self) -> Vec<&RequirementCoverage> {
        self.requirements
            .iter()
            .filter(|r| r.mandatory && r.result == CoverageResult::Unenforceable)
            .collect()
    }

    /// True if every requirement in this report resolved `Enforced`.
    #[must_use]
    pub fn fully_enforced(&self) -> bool {
        self.requirements.iter().all(|r| r.result.is_enforced())
    }
}

/// Linux enforcement coverage: detect the ABI, then delegate.
///
/// If Landlock cannot be detected at all, every requirement present in
/// `caps` is `Unenforceable` — there is no fallback component for
/// filesystem or signal-scope enforcement without Landlock.
#[cfg(target_os = "linux")]
fn linux_enforcement_coverage(caps: &CapabilitySet) -> EnforcementCoverageReport {
    match linux::detect_abi() {
        Ok(abi) => linux_enforcement_coverage_with_abi(caps, &abi),
        Err(err) => {
            let evidence = format!("Landlock ABI detection failed: {err}");
            let mut requirements = Vec::new();

            for fs in caps.fs_capabilities() {
                requirements.push(RequirementCoverage {
                    requirement: format!("filesystem:{} ({})", fs.resolved.display(), fs.access),
                    domain: CoverageDomain::Filesystem,
                    enforcing_component: "none",
                    applied_configuration: "no Landlock ABI detected".to_string(),
                    evidence: evidence.clone(),
                    mandatory: true,
                    result: CoverageResult::Unenforceable,
                });
            }
            if !matches!(
                caps.network_mode(),
                crate::capability::NetworkMode::AllowAll
            ) {
                requirements.push(RequirementCoverage {
                    requirement: format!("network:{:?}", caps.network_mode()),
                    domain: CoverageDomain::Network,
                    enforcing_component: "none",
                    applied_configuration: "no Landlock ABI detected".to_string(),
                    evidence: evidence.clone(),
                    mandatory: true,
                    result: CoverageResult::Unenforceable,
                });
            }
            if caps.signal_mode() == crate::capability::SignalMode::AllowSameSandbox {
                requirements.push(RequirementCoverage {
                    requirement: "signal:AllowSameSandbox".to_string(),
                    domain: CoverageDomain::Signal,
                    enforcing_component: "none",
                    applied_configuration: "no Landlock ABI detected".to_string(),
                    evidence: evidence.clone(),
                    mandatory: true,
                    result: CoverageResult::Unenforceable,
                });
            }

            EnforcementCoverageReport { requirements }
        }
    }
}

/// Linux enforcement coverage for an already-detected ABI.
///
/// Generalizes the same requested/enforced reasoning
/// [`linux::landlock_scope_policy_with_abi`] already applies to signal and
/// abstract-socket scoping, to every domain a `CapabilitySet` can express:
///
/// - Filesystem: base read/write access is enforced at any Landlock ABI.
///   Cross-directory rename/link scoping (`Refer`, V2+), truncate control
///   (`Truncate`, V3+), and TOCTOU-safe execute control (V3+) are reported
///   as `RequiresStrongerEnvironment` when the requested access mode needs
///   them and the ABI lacks them — mirroring the existing dropped-flags
///   warning in `access_to_landlock`/`normalize_path_access`, which already
///   degrades best-effort rather than failing closed, so this is not a new
///   blocking behavior (`mandatory: false`).
/// - Network: `Blocked`/`ProxyOnly` are `Enforced` via native Landlock at
///   V4+; below V4, reported `RequiresStrongerEnvironment` — nono's
///   `apply_auto()` falls back to seccomp-notify, a separate component
///   this report does not probe for (probing it forks a child process,
///   which a coverage report must not do as a side effect).
/// - Signal: mirrors `SignalMode`'s own documented severity.
///   `AllowSameSandbox` is mandatory and already fails closed elsewhere in
///   nono when scoping is unsupported, so it is reported `Unenforceable`
///   here too. `Isolated` is documented as best-effort ("continue without
///   it"), so it is `RequiresStrongerEnvironment` and non-mandatory.
/// - Abstract UNIX socket scoping (`IpcMode::SharedMemoryOnly`): documented
///   best-effort ("older kernels... continue without it"), so
///   non-mandatory `RequiresStrongerEnvironment` below V6.
#[cfg(target_os = "linux")]
fn linux_enforcement_coverage_with_abi(
    caps: &CapabilitySet,
    abi: &linux::DetectedAbi,
) -> EnforcementCoverageReport {
    use crate::capability::{AccessMode, IpcMode, NetworkMode, SignalMode};

    let mut requirements = Vec::new();
    let abi_version = abi.version_string().to_string();

    for fs in caps.fs_capabilities() {
        let mut missing: Vec<&str> = Vec::new();
        if matches!(fs.access, AccessMode::Read | AccessMode::ReadWrite) && !abi.has_execute() {
            missing.push("execute access control is not TOCTOU-safe below Landlock V3");
        }
        if matches!(fs.access, AccessMode::Write | AccessMode::ReadWrite) {
            if !abi.has_refer() {
                missing.push("cross-directory rename/link is unrestricted below Landlock V2");
            }
            if !abi.has_truncate() {
                missing.push("truncate is unrestricted below Landlock V3");
            }
        }

        let requirement = format!("filesystem:{} ({})", fs.resolved.display(), fs.access);
        if missing.is_empty() {
            requirements.push(RequirementCoverage {
                requirement,
                domain: CoverageDomain::Filesystem,
                enforcing_component: "landlock",
                applied_configuration: abi_version.clone(),
                evidence: format!("Landlock {abi_version} enforces the full access set requested"),
                mandatory: true,
                result: CoverageResult::Enforced,
            });
        } else {
            requirements.push(RequirementCoverage {
                requirement,
                domain: CoverageDomain::Filesystem,
                enforcing_component: "landlock",
                applied_configuration: abi_version.clone(),
                evidence: missing.join("; "),
                mandatory: false,
                result: CoverageResult::RequiresStrongerEnvironment,
            });
        }
    }

    match caps.network_mode() {
        NetworkMode::AllowAll => {
            requirements.push(RequirementCoverage {
                requirement: "network:AllowAll".to_string(),
                domain: CoverageDomain::Network,
                enforcing_component: "none",
                applied_configuration: abi_version.clone(),
                evidence: "no network restriction requested".to_string(),
                mandatory: false,
                result: CoverageResult::Enforced,
            });
        }
        mode => {
            if abi.has_network() {
                requirements.push(RequirementCoverage {
                    requirement: format!("network:{mode:?}"),
                    domain: CoverageDomain::Network,
                    enforcing_component: "landlock",
                    applied_configuration: abi_version.clone(),
                    evidence: format!("Landlock {abi_version} enforces TCP filtering natively"),
                    mandatory: true,
                    result: CoverageResult::Enforced,
                });
            } else {
                requirements.push(RequirementCoverage {
                    requirement: format!("network:{mode:?}"),
                    domain: CoverageDomain::Network,
                    enforcing_component: "landlock",
                    applied_configuration: abi_version.clone(),
                    evidence: format!(
                        "Landlock {abi_version} has no native TCP filtering (needs V4+); \
                         apply_auto() falls back to seccomp-notify, a different component \
                         this compile-time report does not probe for"
                    ),
                    mandatory: true,
                    result: CoverageResult::RequiresStrongerEnvironment,
                });
            }
        }
    }

    let signal_requested = !matches!(caps.signal_mode(), SignalMode::AllowAll);
    if signal_requested {
        let mandatory = caps.signal_mode() == SignalMode::AllowSameSandbox;
        if abi.has_scoping() {
            requirements.push(RequirementCoverage {
                requirement: format!("signal:{:?}", caps.signal_mode()),
                domain: CoverageDomain::Signal,
                enforcing_component: "landlock",
                applied_configuration: abi_version.clone(),
                evidence: format!("Landlock {abi_version} enforces LANDLOCK_SCOPE_SIGNAL"),
                mandatory,
                result: CoverageResult::Enforced,
            });
        } else {
            requirements.push(RequirementCoverage {
                requirement: format!("signal:{:?}", caps.signal_mode()),
                domain: CoverageDomain::Signal,
                enforcing_component: "landlock",
                applied_configuration: abi_version.clone(),
                evidence: format!(
                    "Landlock {abi_version} has no scope support (needs V6+); \
                     signal scoping is not enforced"
                ),
                mandatory,
                result: if mandatory {
                    CoverageResult::Unenforceable
                } else {
                    CoverageResult::RequiresStrongerEnvironment
                },
            });
        }
    }

    if caps.ipc_mode() == IpcMode::SharedMemoryOnly {
        if abi.has_scoping() {
            requirements.push(RequirementCoverage {
                requirement: "ipc:SharedMemoryOnly".to_string(),
                domain: CoverageDomain::AbstractUnixSocket,
                enforcing_component: "landlock",
                applied_configuration: abi_version.clone(),
                evidence: format!(
                    "Landlock {abi_version} enforces LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET"
                ),
                mandatory: false,
                result: CoverageResult::Enforced,
            });
        } else {
            requirements.push(RequirementCoverage {
                requirement: "ipc:SharedMemoryOnly".to_string(),
                domain: CoverageDomain::AbstractUnixSocket,
                enforcing_component: "landlock",
                applied_configuration: abi_version.clone(),
                evidence: format!(
                    "Landlock {abi_version} has no scope support (needs V6+); abstract UNIX \
                     socket access is not scoped (documented best-effort: nono continues \
                     without it)"
                ),
                mandatory: false,
                result: CoverageResult::RequiresStrongerEnvironment,
            });
        }
    }

    EnforcementCoverageReport { requirements }
}

/// macOS enforcement coverage via `SupportInfo`.
///
/// Seatbelt is not version-gated the way Landlock's ABI is: `support_info`
/// reports availability, not a tiered feature set, so this path is coarser
/// than the Linux one by design (both are documented explicitly, per plan
/// 05's "Linux/macOS enforcement differences are explicit" requirement,
/// rather than papered over with a shared abstraction). Abstract UNIX
/// socket scoping has no macOS equivalent (no such namespace exists there)
/// and produces no requirement on this platform.
#[cfg(target_os = "macos")]
fn macos_enforcement_coverage(caps: &CapabilitySet) -> EnforcementCoverageReport {
    use crate::capability::{NetworkMode, SignalMode};

    let support = macos::support_info();
    let mut requirements = Vec::new();
    let component: &'static str = if support.is_supported {
        "seatbelt"
    } else {
        "none"
    };
    let result = if support.is_supported {
        CoverageResult::Enforced
    } else {
        CoverageResult::Unenforceable
    };

    for fs in caps.fs_capabilities() {
        requirements.push(RequirementCoverage {
            requirement: format!("filesystem:{} ({})", fs.resolved.display(), fs.access),
            domain: CoverageDomain::Filesystem,
            enforcing_component: component,
            applied_configuration: support.details.clone(),
            evidence: support.details.clone(),
            mandatory: true,
            result,
        });
    }

    if !matches!(caps.network_mode(), NetworkMode::AllowAll) {
        requirements.push(RequirementCoverage {
            requirement: format!("network:{:?}", caps.network_mode()),
            domain: CoverageDomain::Network,
            enforcing_component: component,
            applied_configuration: support.details.clone(),
            evidence: support.details.clone(),
            mandatory: true,
            result,
        });
    }

    if !matches!(caps.signal_mode(), SignalMode::AllowAll) {
        let mandatory = caps.signal_mode() == SignalMode::AllowSameSandbox;
        requirements.push(RequirementCoverage {
            requirement: format!("signal:{:?}", caps.signal_mode()),
            domain: CoverageDomain::Signal,
            enforcing_component: component,
            applied_configuration: support.details.clone(),
            evidence: support.details.clone(),
            mandatory,
            result,
        });
    }

    // Abstract UNIX socket scoping is a Linux-only concept; macOS's IPC
    // mode maps to `ipc-posix-*` Seatbelt rules instead (see `IpcMode`
    // doc comments), which are covered by macOS's own IPC enforcement, not
    // a separate scoping mechanism. Intentionally no requirement emitted
    // for `CoverageDomain::AbstractUnixSocket` on this platform.

    EnforcementCoverageReport { requirements }
}

/// Enforcement coverage on a platform with no sandbox backend at all: every
/// requirement present in `caps` is `Unenforceable`.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn unsupported_enforcement_coverage(caps: &CapabilitySet) -> EnforcementCoverageReport {
    use crate::capability::{NetworkMode, SignalMode};

    let evidence = format!(
        "no sandbox backend is implemented for platform '{}'",
        std::env::consts::OS
    );
    let mut requirements = Vec::new();

    for fs in caps.fs_capabilities() {
        requirements.push(RequirementCoverage {
            requirement: format!("filesystem:{} ({})", fs.resolved.display(), fs.access),
            domain: CoverageDomain::Filesystem,
            enforcing_component: "none",
            applied_configuration: std::env::consts::OS.to_string(),
            evidence: evidence.clone(),
            mandatory: true,
            result: CoverageResult::Unenforceable,
        });
    }
    if !matches!(caps.network_mode(), NetworkMode::AllowAll) {
        requirements.push(RequirementCoverage {
            requirement: format!("network:{:?}", caps.network_mode()),
            domain: CoverageDomain::Network,
            enforcing_component: "none",
            applied_configuration: std::env::consts::OS.to_string(),
            evidence: evidence.clone(),
            mandatory: true,
            result: CoverageResult::Unenforceable,
        });
    }
    if caps.signal_mode() == SignalMode::AllowSameSandbox {
        requirements.push(RequirementCoverage {
            requirement: "signal:AllowSameSandbox".to_string(),
            domain: CoverageDomain::Signal,
            enforcing_component: "none",
            applied_configuration: std::env::consts::OS.to_string(),
            evidence: evidence.clone(),
            mandatory: true,
            result: CoverageResult::Unenforceable,
        });
    }

    EnforcementCoverageReport { requirements }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod coverage_tests {
    use super::*;
    use crate::capability::{AccessMode, IpcMode, SignalMode};

    // ---- Platform-independent: the report type and the placement gate ----
    //
    // These build `RequirementCoverage` values directly rather than through
    // a platform-specific detector, so they run identically on every host
    // this crate builds on and exercise exactly the mechanism every
    // platform path (`linux_enforcement_coverage_with_abi`,
    // `macos_enforcement_coverage`, `unsupported_enforcement_coverage`)
    // feeds into: `EnforcementCoverageReport::unenforceable_mandatory()`
    // and `Sandbox::placement_by_coverage()`.

    fn enforced(requirement: &str) -> RequirementCoverage {
        RequirementCoverage {
            requirement: requirement.to_string(),
            domain: CoverageDomain::Filesystem,
            enforcing_component: "landlock",
            applied_configuration: "V6".to_string(),
            evidence: "fully enforced".to_string(),
            mandatory: true,
            result: CoverageResult::Enforced,
        }
    }

    #[test]
    fn fully_enforced_report_is_fully_enforced_and_does_not_block() {
        let report = EnforcementCoverageReport {
            requirements: vec![enforced("filesystem:/a"), enforced("filesystem:/b")],
        };
        assert!(report.fully_enforced());
        assert!(report.unenforceable_mandatory().is_empty());
        assert!(Sandbox::placement_by_coverage(&report).is_ok());
    }

    #[test]
    fn non_mandatory_requires_stronger_environment_does_not_block() {
        // A requirement outside current coverage that resolves
        // REQUIRES_STRONGER_ENVIRONMENT and is not mandatory (nono's own
        // best-effort domains: SignalMode::Isolated, IpcMode::SharedMemoryOnly
        // below Landlock V6) must be reported, but must not block placement —
        // it is "not a pass" without being an admission blocker.
        let mut degraded = enforced("ipc:SharedMemoryOnly");
        degraded.domain = CoverageDomain::AbstractUnixSocket;
        degraded.mandatory = false;
        degraded.result = CoverageResult::RequiresStrongerEnvironment;
        degraded.evidence = "Landlock V5 has no scope support (needs V6+)".to_string();

        let report = EnforcementCoverageReport {
            requirements: vec![enforced("filesystem:/a"), degraded],
        };

        assert!(
            !report.fully_enforced(),
            "not every requirement is Enforced"
        );
        assert!(
            report.unenforceable_mandatory().is_empty(),
            "non-mandatory degradation must not appear as a blocking requirement"
        );
        assert!(
            Sandbox::placement_by_coverage(&report).is_ok(),
            "REQUIRES_STRONGER_ENVIRONMENT on a non-mandatory requirement must not block admission"
        );
    }

    #[test]
    fn mandatory_unenforceable_blocks_placement() {
        // D-33's placement rule: a mandatory requirement outside current
        // coverage that resolves UNENFORCEABLE must block admission, not
        // silently degrade — this is the core behavior NONO-COV-001 adds.
        let mut blocking = enforced("signal:AllowSameSandbox");
        blocking.domain = CoverageDomain::Signal;
        blocking.mandatory = true;
        blocking.result = CoverageResult::Unenforceable;
        blocking.evidence =
            "Landlock V5 has no scope support (needs V6+); signal scoping is not enforced"
                .to_string();

        let report = EnforcementCoverageReport {
            requirements: vec![enforced("filesystem:/a"), blocking],
        };

        assert!(!report.fully_enforced());
        let names: Vec<&str> = report
            .unenforceable_mandatory()
            .iter()
            .map(|r| r.requirement.as_str())
            .collect();
        assert_eq!(names, vec!["signal:AllowSameSandbox"]);

        let err = Sandbox::placement_by_coverage(&report)
            .expect_err("a mandatory UNENFORCEABLE requirement must refuse admission");
        let msg = err.to_string();
        assert!(
            msg.contains("signal:AllowSameSandbox"),
            "error must name the blocking requirement, got: {msg}"
        );
    }

    #[test]
    fn coverage_result_is_enforced_is_true_only_for_enforced() {
        assert!(CoverageResult::Enforced.is_enforced());
        assert!(!CoverageResult::RequiresStrongerEnvironment.is_enforced());
        assert!(!CoverageResult::Unenforceable.is_enforced());
    }

    // ---- Linux: the real ABI-driven detector ----
    //
    // Compiled and run only on Linux; see the module doc on
    // `linux_enforcement_coverage_with_abi` for why macOS cannot exercise
    // the same ABI-tiered gap today (Seatbelt is not version-gated), and
    // the plan-05 requirement that Linux/macOS differences be explicit
    // rather than papered over.
    #[cfg(target_os = "linux")]
    mod linux_coverage {
        use super::*;
        use crate::sandbox::linux::DetectedAbi;
        use landlock::ABI;

        #[test]
        fn fs_read_below_v3_reports_requires_stronger_environment() {
            // V1 lacks TOCTOU-safe execute control (has_execute() needs V3+),
            // so a Read grant on V1 is outside current ABI coverage: it must
            // be reported, not silently treated as fully covered.
            let dir = tempfile::tempdir().expect("tempdir");
            let caps = CapabilitySet::new()
                .allow_path(dir.path(), AccessMode::Read)
                .unwrap();
            let report = linux_enforcement_coverage_with_abi(&caps, &DetectedAbi::new(ABI::V1));
            let fs = report
                .requirements
                .iter()
                .find(|r| r.domain == CoverageDomain::Filesystem)
                .expect("a filesystem requirement must be reported");
            assert_eq!(fs.result, CoverageResult::RequiresStrongerEnvironment);
            assert!(
                !fs.mandatory,
                "fs degradation is best-effort, matching access_to_landlock"
            );
            assert!(!report.fully_enforced());
            // Non-mandatory: must not block placement.
            assert!(Sandbox::placement_by_coverage(&report).is_ok());
        }

        #[test]
        fn fs_read_at_v6_is_fully_enforced() {
            let dir = tempfile::tempdir().expect("tempdir");
            let caps = CapabilitySet::new()
                .allow_path(dir.path(), AccessMode::Read)
                .unwrap();
            let report = linux_enforcement_coverage_with_abi(&caps, &DetectedAbi::new(ABI::V6));
            let fs = report
                .requirements
                .iter()
                .find(|r| r.domain == CoverageDomain::Filesystem)
                .expect("a filesystem requirement must be reported");
            assert_eq!(fs.result, CoverageResult::Enforced);
            assert!(fs.mandatory);
        }

        #[test]
        fn network_blocked_below_v4_reports_requires_stronger_environment() {
            let caps = CapabilitySet::new().block_network();
            let report = linux_enforcement_coverage_with_abi(&caps, &DetectedAbi::new(ABI::V3));
            let net = report
                .requirements
                .iter()
                .find(|r| r.domain == CoverageDomain::Network)
                .expect("a network requirement must be reported");
            assert_eq!(net.result, CoverageResult::RequiresStrongerEnvironment);
            assert!(net.mandatory);
        }

        #[test]
        fn signal_allow_same_sandbox_below_v6_is_unenforceable_and_blocks() {
            // The one case that is both mandatory and can resolve
            // UNENFORCEABLE today: SignalMode::AllowSameSandbox already
            // fails closed elsewhere in nono (requested_scopes) when the
            // kernel lacks V6 scope support; the coverage report must
            // surface this as a structured, reportable UNENFORCEABLE
            // result, and the placement rule must block on it.
            let caps = CapabilitySet::new().set_signal_mode(SignalMode::AllowSameSandbox);
            let report = linux_enforcement_coverage_with_abi(&caps, &DetectedAbi::new(ABI::V5));
            let signal = report
                .requirements
                .iter()
                .find(|r| r.domain == CoverageDomain::Signal)
                .expect("a signal requirement must be reported");
            assert_eq!(signal.result, CoverageResult::Unenforceable);
            assert!(signal.mandatory);
            assert!(Sandbox::placement_by_coverage(&report).is_err());
        }

        #[test]
        fn signal_isolated_below_v6_degrades_without_blocking() {
            // Isolated is documented best-effort ("continue without it"):
            // must be reported as not-fully-covered, but must not block.
            let caps = CapabilitySet::new().set_signal_mode(SignalMode::Isolated);
            let report = linux_enforcement_coverage_with_abi(&caps, &DetectedAbi::new(ABI::V5));
            let signal = report
                .requirements
                .iter()
                .find(|r| r.domain == CoverageDomain::Signal)
                .expect("a signal requirement must be reported");
            assert_eq!(signal.result, CoverageResult::RequiresStrongerEnvironment);
            assert!(!signal.mandatory);
            assert!(Sandbox::placement_by_coverage(&report).is_ok());
        }

        #[test]
        fn abstract_unix_socket_below_v6_degrades_without_blocking() {
            let caps = CapabilitySet::new().set_ipc_mode(IpcMode::SharedMemoryOnly);
            let report = linux_enforcement_coverage_with_abi(&caps, &DetectedAbi::new(ABI::V5));
            let ipc = report
                .requirements
                .iter()
                .find(|r| r.domain == CoverageDomain::AbstractUnixSocket)
                .expect("an abstract-unix-socket requirement must be reported");
            assert_eq!(ipc.result, CoverageResult::RequiresStrongerEnvironment);
            assert!(!ipc.mandatory);
            assert!(Sandbox::placement_by_coverage(&report).is_ok());
        }

        #[test]
        fn no_requirements_present_yields_empty_report() {
            // `CapabilitySet::new()`'s *defaults* (`SignalMode::Isolated`,
            // `IpcMode::SharedMemoryOnly`) are themselves requests — nono
            // defaults to its most restrictive posture, not to "nothing
            // requested". An empty report needs every mode explicitly
            // relaxed to its least-restrictive value.
            let caps = CapabilitySet::new()
                .set_signal_mode(SignalMode::AllowAll)
                .set_ipc_mode(IpcMode::Full);
            let report = linux_enforcement_coverage_with_abi(&caps, &DetectedAbi::new(ABI::V1));
            assert!(report.requirements.is_empty());
            assert!(report.fully_enforced());
            assert!(Sandbox::placement_by_coverage(&report).is_ok());
        }
    }

    // ---- macOS: the SupportInfo-driven detector, exercised end-to-end ----
    //
    // Runs on this crate's macOS CI/dev hosts. Demonstrates the
    // plan-05-required fact directly: macOS's coverage path is coarser
    // than Linux's (Seatbelt is not ABI-tiered), so it does not surface a
    // "below-some-version" gap the way Linux does — every mode nono can
    // express is fully enforced by Seatbelt today, which the network and
    // signal cases below assert explicitly rather than assume.
    #[cfg(target_os = "macos")]
    mod macos_coverage {
        use super::*;

        #[test]
        fn full_capability_set_is_fully_enforced_via_seatbelt() {
            let dir = tempfile::tempdir().expect("tempdir");
            let caps = CapabilitySet::new()
                .allow_path(dir.path(), AccessMode::ReadWrite)
                .unwrap()
                .block_network()
                .set_signal_mode(SignalMode::AllowSameSandbox);
            let report = Sandbox::enforcement_coverage(&caps);

            assert!(!report.requirements.is_empty());
            for req in &report.requirements {
                assert_eq!(
                    req.result,
                    CoverageResult::Enforced,
                    "expected Enforced for {:?}, got {:?} ({})",
                    req.requirement,
                    req.result,
                    req.evidence
                );
                assert_eq!(req.enforcing_component, "seatbelt");
            }
            assert!(report.fully_enforced());
            assert!(Sandbox::placement_by_coverage(&report).is_ok());
        }

        #[test]
        fn abstract_unix_socket_domain_is_not_modeled_on_macos() {
            // Documented gap: there is no abstract-socket namespace on
            // macOS, so this domain is deliberately left unreported here
            // rather than silently mapped onto an unrelated mechanism.
            let caps = CapabilitySet::new().set_ipc_mode(IpcMode::SharedMemoryOnly);
            let report = Sandbox::enforcement_coverage(&caps);
            assert!(
                !report
                    .requirements
                    .iter()
                    .any(|r| r.domain == CoverageDomain::AbstractUnixSocket),
                "macOS has no abstract-unix-socket equivalent to report coverage for"
            );
        }

        #[test]
        fn network_allow_all_requirement_is_not_mandatory() {
            let caps = CapabilitySet::new();
            let report = Sandbox::enforcement_coverage(&caps);
            assert!(
                !report
                    .requirements
                    .iter()
                    .any(|r| r.domain == CoverageDomain::Network),
                "AllowAll requests no network restriction; nothing to report"
            );
        }

        #[test]
        fn empty_capability_set_yields_empty_report() {
            // `CapabilitySet::new()`'s *defaults* (`SignalMode::Isolated`,
            // `IpcMode::SharedMemoryOnly`) are themselves requests — nono
            // defaults to its most restrictive posture, not to "nothing
            // requested". An empty report needs every mode explicitly
            // relaxed to its least-restrictive value.
            let caps = CapabilitySet::new()
                .set_signal_mode(SignalMode::AllowAll)
                .set_ipc_mode(IpcMode::Full);
            let report = Sandbox::enforcement_coverage(&caps);
            assert!(report.requirements.is_empty());
            assert!(report.fully_enforced());
            assert!(Sandbox::placement_by_coverage(&report).is_ok());
        }
    }
}
