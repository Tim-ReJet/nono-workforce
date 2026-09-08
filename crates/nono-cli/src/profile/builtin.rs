//! Built-in profiles compiled into the nono binary
//!
//! Profiles are defined declaratively in `policy.json` under the `profiles` key.
//! This module delegates to the policy resolver for loading and listing.

use super::Profile;

/// Get a built-in profile by name
pub fn get_builtin(name: &str) -> Option<Profile> {
    crate::policy::get_policy_profile(name).ok().flatten()
}

/// List all built-in profile names
pub fn list_builtin() -> Vec<String> {
    crate::policy::list_policy_profiles().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::WorkdirAccess;

    #[test]
    fn test_claude_code_no_longer_inbuilt() {
        // Removed in v0.43.0: claude-code is now shipped via the registry pack
        // `nolabs-ai/claude` (formerly `always-further/claude`) and resolved
        // through the user-profile symlink, not the embedded policy.json.
        assert!(get_builtin("claude-code").is_none());
        assert!(get_builtin("claude-no-kc").is_none());
    }

    #[test]
    fn test_opencode_no_longer_inbuilt() {
        // Removed: opencode is now shipped via the registry pack
        // `nolabs-ai/opencode` (formerly `always-further/opencode`), not embedded in policy.json.
        assert!(get_builtin("opencode").is_none());
    }

    #[test]
    fn test_get_builtin_default() {
        let profile = get_builtin("default").expect("Profile not found");
        assert_eq!(profile.meta.name, "default");
        assert_eq!(profile.workdir.access, WorkdirAccess::None);
        assert!(!profile.interactive);
        assert!(!profile.network.block);
    }

    #[test]
    fn test_openclaw_no_longer_inbuilt() {
        // Removed in v0.71.0: openclaw is now shipped via the registry pack nolabs-ai/openclaw.
        assert!(get_builtin("openclaw").is_none());
    }

    #[test]
    fn test_swival_no_longer_inbuilt() {
        // Removed in v0.71.0: swival is now shipped via the registry pack jedisct1/swival,
        // officially maintained by Swival's creator under their own namespace.
        assert!(get_builtin("swival").is_none());
    }

    #[test]
    fn test_get_builtin_nonexistent() {
        assert!(get_builtin("nonexistent").is_none());
    }

    /// Canonical-schema invariant: every built-in profile must resolve to
    /// non-empty canonical sections after the #594 migration. Either the
    /// profile contributes groups to `groups.include` (directly or through
    /// `extends: default`), or it carries filesystem.allow entries — any
    /// empty profile here likely lost data during JSON migration.
    #[test]
    fn test_all_builtins_use_canonical_schema_only() {
        for name in list_builtin() {
            let profile =
                get_builtin(&name).unwrap_or_else(|| panic!("built-in '{}' should load", name));
            assert!(
                !profile.groups.include.is_empty() || !profile.filesystem.allow.is_empty(),
                "{name} has empty canonical sections"
            );
        }
    }

    #[test]
    fn test_list_builtin() {
        let profiles = list_builtin();
        assert!(profiles.contains(&"default".to_string()));
        assert!(profiles.contains(&"linux-host-compat".to_string()));
        assert!(profiles.contains(&"workforce-host".to_string()));
        assert!(profiles.contains(&"cell-repository".to_string()));
        // Profiles that ship via registry packs instead of as built-ins:
        //   claude-code → nolabs-ai/claude   (formerly always-further/claude, removed v0.43.0)
        //   codex       → nolabs-ai/codex    (formerly always-further/codex, removed v0.43.0)
        //   opencode    → nolabs-ai/opencode (formerly always-further/opencode, removed)
        //   openclaw    → nolabs-ai/openclaw (removed v0.71.0)
        //   swival      → jedisct1/swival   (removed v0.71.0; official namespace of Swival's creator)
        // Tool Sandbox examples should also live outside embedded built-ins.
        assert!(!profiles.contains(&"claude-code".to_string()));
        assert!(!profiles.contains(&"claude-no-kc".to_string()));
        assert!(!profiles.contains(&"codex".to_string()));
        assert!(!profiles.contains(&"linux-tool-sandbox-git-ssh".to_string()));
        assert!(!profiles.contains(&"opencode".to_string()));
        assert!(!profiles.contains(&"openclaw".to_string()));
        assert!(!profiles.contains(&"swival".to_string()));
    }

    #[test]
    fn test_profile_group_merging() {
        // Use linux-host-compat as a representative built-in that extends
        // `default` and adds its own groups.
        let profile = get_builtin("linux-host-compat").expect("Profile not found");
        // Should have default profile groups (inherited via extends).
        assert!(
            profile
                .groups
                .include
                .contains(&"deny_credentials".to_string())
        );
        // Should have profile-specific groups
        assert!(
            profile
                .groups
                .include
                .contains(&"linux_runtime_state".to_string())
        );
    }

    #[test]
    fn test_profile_exclusion_mechanism() {
        // Verify that built-in profiles resolve exclusions through the shared
        // group-exclusion path. Current embedded profiles do not exclude any.
        let profile = get_builtin("linux-host-compat").expect("Profile not found");
        let default = get_builtin("default").expect("default profile");
        // All default groups should be present since embedded exclusions are empty.
        for group in &default.groups.include {
            assert!(
                profile.groups.include.contains(group),
                "linux-host-compat should contain default profile group '{}'",
                group
            );
        }
    }

    #[test]
    fn test_default_profile_group_set_is_explicit() {
        let profile = get_builtin("default").expect("default profile");
        let mut expected = vec![
            "dangerous_commands".to_string(),
            "dangerous_commands_linux".to_string(),
            "dangerous_commands_macos".to_string(),
            "deny_browser_data_linux".to_string(),
            "deny_browser_data_macos".to_string(),
            "deny_credentials".to_string(),
            "deny_keychains_linux".to_string(),
            "deny_keychains_macos".to_string(),
            "deny_macos_private".to_string(),
            "deny_shell_configs".to_string(),
            "deny_shell_history".to_string(),
            "homebrew_linux".to_string(),
            "homebrew_macos".to_string(),
            "system_read_linux_core".to_string(),
            "system_read_macos".to_string(),
            "system_write_linux".to_string(),
            "system_write_macos".to_string(),
            "user_tools".to_string(),
        ];
        let mut actual = profile.groups.include.clone();
        expected.sort();
        actual.sort();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_embedded_profiles_extend_default() {
        let policy = crate::policy::load_embedded_policy().expect("load embedded policy");
        for (name, def) in &policy.profiles {
            if name == "default" {
                continue;
            }
            assert_eq!(
                def.extends.as_deref(),
                Some("default"),
                "embedded profile '{}' should extend default",
                name
            );
        }
    }

    #[test]
    fn test_linux_host_compat_profile_groups() {
        let profile = get_builtin("linux-host-compat").expect("Profile not found");
        assert!(
            profile
                .groups
                .include
                .contains(&"linux_runtime_state".to_string())
        );
        assert!(
            profile
                .groups
                .include
                .contains(&"linux_sysfs_read".to_string())
        );
        assert!(
            profile
                .groups
                .include
                .contains(&"linux_temp_read".to_string())
        );
    }

    #[test]
    fn test_linux_host_compat_includes_runtime_state_and_sysfs_and_temp() {
        let profile = get_builtin("linux-host-compat").expect("Profile not found");
        assert!(
            profile
                .groups
                .include
                .contains(&"linux_runtime_state".to_string()),
            "linux-host-compat should include linux_runtime_state"
        );
        assert!(
            profile
                .groups
                .include
                .contains(&"linux_sysfs_read".to_string()),
            "linux-host-compat should include linux_sysfs_read"
        );
        assert!(
            profile
                .groups
                .include
                .contains(&"linux_temp_read".to_string()),
            "linux-host-compat should include linux_temp_read"
        );
    }

    /// NONO-001: `workforce-host` is the Workforce-added global profile that
    /// hosts a locally supervised Cell under deployment-bound identity (no
    /// SPIFFE/SPIRE — ADR-028 D-12 amended default). It must resolve, must
    /// not grant workdir or network access, and must not add filesystem
    /// entries beyond what it inherits from `default` (which is empty).
    #[test]
    fn test_workforce_host_profile_resolves_with_no_workdir_or_network() {
        let profile = get_builtin("workforce-host").expect("workforce-host should resolve");
        assert_eq!(profile.meta.name, "workforce-host");
        assert_eq!(profile.workdir.access, WorkdirAccess::None);
        assert!(
            profile.network.block,
            "workforce-host must keep network.block = true"
        );
        let default = get_builtin("default").expect("default profile");
        assert_eq!(
            profile.filesystem.allow, default.filesystem.allow,
            "workforce-host must not add filesystem.allow beyond default"
        );
        assert!(
            profile.env_credentials.mappings.is_empty(),
            "workforce-host must not set a default credential grant"
        );
    }

    /// NONO-001: `cell-repository` is the Workforce-added Cell profile for an
    /// ordinary repository-editing task admitted under the local fast path
    /// (ADR-028 D-41). It must resolve, must be able to read+write the
    /// admitted working directory, must route network through the proxy
    /// (never `Unrestricted`), must still inherit `default`'s deny_* groups,
    /// and must not set a default credential grant.
    #[test]
    fn test_cell_repository_profile_resolves_scoped_readwrite_proxy_only() {
        let profile = get_builtin("cell-repository").expect("cell-repository should resolve");
        assert_eq!(profile.meta.name, "cell-repository");
        assert_ne!(
            profile.workdir.access,
            WorkdirAccess::None,
            "cell-repository must be able to edit its admitted working directory"
        );
        assert_eq!(profile.workdir.access, WorkdirAccess::ReadWrite);
        assert!(
            !profile.network.block,
            "cell-repository needs network for an ordinary repository task"
        );
        assert!(
            profile.network.resolved_network_profile().is_some(),
            "cell-repository network must be routed through a named proxy profile, not left Unrestricted"
        );
        for group in [
            "deny_credentials",
            "deny_keychains_macos",
            "deny_keychains_linux",
            "deny_shell_history",
            "deny_shell_configs",
        ] {
            assert!(
                profile.groups.include.contains(&group.to_string()),
                "cell-repository must inherit default's '{}' group",
                group
            );
        }
        assert!(
            profile.env_credentials.mappings.is_empty(),
            "cell-repository must not set a default credential grant"
        );
    }

    /// NONO-003: `cell-repository` profile hygiene (BATCH_3_REPORT.md §7
    /// items 6-7, §5.2 (e)-(f), §5.1 PR-02).
    ///
    /// Asserts on the resolved `Profile` struct and the resolved
    /// `CapabilitySet` built from it (not the `--format manifest` JSON
    /// display, which is a separate, lossier serialization path):
    ///
    /// 1. `filesystem.read` carries the profile-owned `/etc` grant directly
    ///    (TLS-trust intent stated by cell-repository itself, not only
    ///    inherited incidentally through `system_read_macos`).
    /// 2. The merged, effective group set no longer includes
    ///    `system_write_macos`/`system_write_linux` (the source of the
    ///    inherited blanket temp-write grant) or the deprecated,
    ///    not-enforced-for-child-processes `dangerous_commands*` groups.
    /// 3. The resolved `CapabilitySet` grants no write access on
    ///    `/private/tmp`, `/tmp`, `/private/var/folders`, `/var/folders`,
    ///    or a `$TMPDIR`-resolved path, while still granting read access
    ///    reaching `/etc` (via its canonicalized `/private/etc`) and write
    ///    access on the narrow device-node set needed to run at all.
    /// 4. The resolved `CapabilitySet` carries no `blocked_commands` —
    ///    `security.blocked_commands` is schema-deprecated and "not
    ///    enforced for child processes", so cell-repository should not
    ///    claim a command-denylist boundary it cannot enforce.
    #[test]
    fn test_cell_repository_profile_hygiene_etc_read_no_tmp_write_no_dangerous_commands() {
        use crate::capability_ext::CapabilitySetExt;

        let profile = get_builtin("cell-repository").expect("cell-repository should resolve");

        // (1) Profile-owned /etc read grant, stated directly (not only via
        // an inherited group).
        assert!(
            profile.filesystem.read.iter().any(|p| p == "/etc"),
            "cell-repository must declare its own '/etc' read grant; got {:?}",
            profile.filesystem.read
        );

        // (2) Merged/effective groups drop the blanket-temp-write and
        // dangerous_commands* sources.
        for excluded in [
            "system_write_macos",
            "system_write_linux",
            "dangerous_commands",
            "dangerous_commands_macos",
            "dangerous_commands_linux",
        ] {
            assert!(
                !profile.groups.include.contains(&excluded.to_string()),
                "cell-repository's merged groups must not include '{}'; got {:?}",
                excluded,
                profile.groups.include
            );
        }
        // Still inherits `default`'s read-only system paths (unaffected by
        // this change) so the profile stays usable.
        assert!(
            profile
                .groups
                .include
                .contains(&"system_read_macos".to_string())
        );

        // (3) + (4): resolve an actual CapabilitySet the way the sandbox
        // launcher would, and inspect the concrete grants.
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let home = tempfile::Builder::new()
            .prefix("nono-cell-repository-hygiene-home-")
            .tempdir_in(std::env::current_dir().expect("cwd"))
            .expect("home tempdir");
        std::fs::create_dir_all(home.path().join("Library/Keychains")).expect("mkdir keychains");
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("HOME", home.path().to_str().expect("home utf8")),
            (
                "XDG_CONFIG_HOME",
                home.path().join(".config").to_str().expect("config utf8"),
            ),
            (
                "XDG_DATA_HOME",
                home.path()
                    .join(".local/share")
                    .to_str()
                    .expect("data utf8"),
            ),
            (
                "XDG_STATE_HOME",
                home.path()
                    .join(".local/state")
                    .to_str()
                    .expect("state utf8"),
            ),
            (
                "XDG_CACHE_HOME",
                home.path().join(".cache").to_str().expect("cache utf8"),
            ),
        ]);

        let workdir = tempfile::Builder::new()
            .prefix("nono-cell-repository-hygiene-workdir-")
            .tempdir_in(std::env::current_dir().expect("cwd"))
            .expect("workdir");
        let args = crate::cli::SandboxArgs::default();

        let prepared = nono::CapabilitySet::from_profile(&profile, workdir.path(), &args)
            .expect("cell-repository should build capabilities");
        let caps = prepared.caps;

        let tmp_like = [
            "/private/tmp",
            "/tmp",
            "/private/var/folders",
            "/var/folders",
        ];
        for cap in caps.fs_capabilities() {
            let resolved = cap.resolved.to_string_lossy();
            let is_tmp_like = tmp_like.iter().any(|p| resolved.starts_with(p));
            let is_tmpdir = std::env::var("TMPDIR")
                .ok()
                .and_then(|t| std::fs::canonicalize(&t).ok())
                .is_some_and(|canon| cap.resolved.starts_with(&canon));
            if is_tmp_like || is_tmpdir {
                assert_ne!(
                    cap.access,
                    nono::AccessMode::Write,
                    "cell-repository must not grant write on tmp-like path {}",
                    cap.resolved.display()
                );
                assert_ne!(
                    cap.access,
                    nono::AccessMode::ReadWrite,
                    "cell-repository must not grant readwrite on tmp-like path {}",
                    cap.resolved.display()
                );
            }
        }

        // The /etc grant is reachable — its canonical target /private/etc
        // is read-accessible (macOS resolves /etc -> /private/etc; on
        // Linux /etc is not a symlink so this is the same path).
        assert!(
            caps.fs_capabilities().iter().any(|cap| {
                let resolved = cap.resolved.to_string_lossy();
                (resolved == "/etc" || resolved == "/private/etc")
                    && matches!(cap.access, nono::AccessMode::Read | nono::AccessMode::ReadWrite)
            }),
            "cell-repository must grant read reaching /etc"
        );

        // Narrow device-write set still present so the sandboxed process
        // can run at all (stdout/stderr/null redirection etc.).
        assert!(
            caps.fs_capabilities().iter().any(|cap| {
                let resolved = cap.resolved.to_string_lossy();
                (resolved == "/dev/null" || resolved == "/dev")
                    && matches!(
                        cap.access,
                        nono::AccessMode::Write | nono::AccessMode::ReadWrite
                    )
            }),
            "cell-repository must still grant device write access to run"
        );

        // (4) No enforced-nowhere command denylist claimed.
        assert!(
            caps.blocked_commands().is_empty(),
            "cell-repository must not carry blocked_commands (schema-deprecated, \
             not enforced for child processes); got {:?}",
            caps.blocked_commands()
        );
    }

    /// Regression test: verifies that all built-in profiles — regardless of
    /// their signal_mode setting — will produce Seatbelt rules that allow
    /// signaling child processes within the same sandbox.
    ///
    /// Background: the Seatbelt generator previously emitted only
    /// `(allow signal (target self))` for `signal_mode: isolated`, which
    /// blocked `kill(child_pid, sig)` on children that inherited the sandbox.
    /// This caused orphan process accumulation and progressive keyboard lag.
    ///
    /// The fix is in the Seatbelt generation layer (macos.rs): both `Isolated`
    /// and `AllowSameSandbox` now emit `(target same-sandbox)`, matching Linux
    /// where Landlock's `LANDLOCK_SCOPE_SIGNAL` cannot distinguish the two.
    #[test]
    fn test_all_profiles_signal_mode_resolves() {
        use crate::capability_ext::CapabilitySetExt;
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let home = tempfile::Builder::new()
            .prefix("nono-builtin-profile-home-")
            .tempdir_in(std::env::current_dir().expect("cwd"))
            .expect("home tempdir");
        std::fs::create_dir_all(home.path().join("Library/Keychains")).expect("mkdir keychains");
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("HOME", home.path().to_str().expect("home utf8")),
            (
                "XDG_CONFIG_HOME",
                home.path().join(".config").to_str().expect("config utf8"),
            ),
            (
                "XDG_DATA_HOME",
                home.path()
                    .join(".local/share")
                    .to_str()
                    .expect("data utf8"),
            ),
            (
                "XDG_STATE_HOME",
                home.path()
                    .join(".local/state")
                    .to_str()
                    .expect("state utf8"),
            ),
            (
                "XDG_CACHE_HOME",
                home.path().join(".cache").to_str().expect("cache utf8"),
            ),
        ]);

        let workdir = tempfile::Builder::new()
            .prefix("nono-builtin-profile-workdir-")
            .tempdir_in(std::env::current_dir().expect("cwd"))
            .expect("workdir");
        let args = crate::cli::SandboxArgs::default();

        let profiles = list_builtin();
        for name in &profiles {
            let profile = get_builtin(name)
                .unwrap_or_else(|| panic!("built-in profile '{}' should load", name));

            let prepared = nono::CapabilitySet::from_profile(&profile, workdir.path(), &args)
                .unwrap_or_else(|e| panic!("profile '{}' should build caps: {}", name, e));
            let caps = prepared.caps;

            // Whether the profile uses Isolated or AllowSameSandbox, the
            // Seatbelt generator must emit same-sandbox signal rules.
            // This is verified by the library tests in macos.rs; here we
            // just confirm the CapabilitySet builds without error and has
            // a signal mode that the generator handles correctly.
            let mode = caps.signal_mode();
            assert!(
                matches!(
                    mode,
                    nono::SignalMode::Isolated
                        | nono::SignalMode::AllowSameSandbox
                        | nono::SignalMode::AllowAll
                ),
                "profile '{}' has unexpected signal_mode {:?}",
                name,
                mode,
            );
        }
    }
}
