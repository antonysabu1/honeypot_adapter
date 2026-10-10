"""Virtual Package Manager for the honeypot VirtualOS.

Provides a stateful simulated package management subsystem entirely against
VirtualOS state.  Supports a controlled subset of apt/apt-get/dpkg semantics
including query, list, status, install, remove, and purge.  Package operations
may update virtual filesystem entries, register/unregister virtual services,
create/remove virtual processes, and expose/remove virtual network listeners
through validated VirtualOS APIs.

All package metadata and state remains simulated and deterministic; no real
host package managers are ever invoked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# ── Package identification ────────────────────────────────────────────────

_PACKAGE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


def valid_package_name(name: str) -> bool:
    """Return True if *name* is a valid package name syntax."""
    return bool(_PACKAGE_NAME_RE.match(name))


# ── VirtualPackage state model ────────────────────────────────────────────

@dataclass
class VirtualPackage:
    """Represents a single virtual package in the honeypot's package database."""

    name: str
    version: str = "0"
    architecture: str = "all"
    # Installation state
    installed: bool = False
    # Dependencies: package name -> version requirement string
    dependencies: Dict[str, str] = field(default_factory=dict)
    # Pseudo-packages / conffiles tracked as lightweight entries
    conffiles: FrozenSet[str] = field(default_factory=frozenset)
    # Associated virtual service name, if any
    associated_service: str | None = None
    # Associated virtual process count (processes launched by this package)
    process_count: int = 0
    # Whether the package is a virtual/metapackage
    is_meta: bool = False
    # Short description
    description: str = ""

    def is_installable(self, db: "PackageManager") -> bool:
        """Check whether all dependencies are satisfied in *db*."""
        for dep_name, req_version in self.dependencies.items():
            dep_pkg = db._packages.get(dep_name)
            if dep_pkg is None:
                return False  # dependency not installed at all
            if not dep_pkg.installed:
                return False  # dependency not installed
            # Simple version comparison: we only store version strings;
            # for a full implementation use pkg-resources or similar.
            # Here we just require the dependency to be installed.
        return True

    def __str__(self) -> str:
        return self.name


# ── PackageManager ────────────────────────────────────────────────────────

class PackageManager:
    """Manages the virtual package database for the honeypot VirtualOS.

    Responsibilities
    -----------------
    * Maintain the authoritative package state (single source of truth)
    * Simulate apt/apt-get/dpkg subset: query, list, status, install, remove, purge
    * Dependency validation against the virtual package database
    * Cross-component integration: filesystem, services, processes, network
    * Persistence integration so package state survives restart
    * Telemetry integration so package operations are recorded safely
    * Enforce deterministic, safe behavior with no host interaction
    """

    # ── Bootstrapping: initial package database from Linux persona ──────────

    # Baseline packages that reflect a minimal Ubuntu 22.04 server installation.
    # These are deterministic and versioned to ensure reproducible behavior.
    _BASELINE_PACKAGES: List[VirtualPackage] = [
        VirtualPackage(name="bash", version="5.1", architecture="amd64", installed=True,
                       description="Bourne Again SHell"),
        VirtualPackage(name="coreutils", version="8.32", architecture="amd64", installed=True,
                       description="Core GNU utilities"),
        VirtualPackage(name="dpkg", version="1.21.15", architecture="amd64", installed=True,
                       description="Debian package manager"),
        VirtualPackage(name="apt", version="2.4.0", architecture="amd64", installed=True,
                       description="Advanced Package Tool"),
        VirtualPackage(name="apt-get", version="2.4.0", architecture="amd64", installed=True,
                       description="Advanced Package Tool"),
        VirtualPackage(name="sshd", version="9.5p1", architecture="amd64", installed=True,
                       description="OpenSSH server associated service"),
        VirtualPackage(name="cron", version="5.0", architecture="amd64", installed=True,
                       description="Cron daemon associated service"),
        VirtualPackage(name="rsyslog", version="8.2401.0", architecture="amd64", installed=True,
                       description="System logging daemon"),
        VirtualPackage(name="less", version="570", architecture="amd64", installed=True,
                       description="Pager program"),
        VirtualPackage(name="grep", version="3.9", architecture="amd64", installed=True,
                       description="Pattern matching utility"),
        VirtualPackage(name="find", version="4.8.0", architecture="amd64", installed=True,
                       description="File searching utility"),
        VirtualPackage(name="procps", version="3.3.17", architecture="amd64", installed=True,
                       description="System monitoring utilities"),
        VirtualPackage(name="util-linux", version="2.38.1", architecture="amd64", installed=True,
                       description="Miscellaneous system utilities"),
        VirtualPackage(name="libc6", version="2.35", architecture="amd64", installed=True,
                       description="C library"),
        VirtualPackage(name="libssl3", version="3.0.2", architecture="amd64", installed=True,
                       description="SSL shared library"),
        VirtualPackage(name="bash-completion", version="2.11", architecture="amd64", installed=True,
                       description="Bash completion facilities"),
        VirtualPackage(name="openssh-server", version="9.5p1", architecture="amd64", installed=True,
                       description="OpenSSH server"),
    ]

    def __init__(self, max_packages: int | None = None) -> None:
        self._packages: Dict[str, VirtualPackage] = {}
        self._max_packages = max_packages
        # Seed from baseline
        for pkg in self._BASELINE_PACKAGES:
            self._packages[pkg.name] = pkg
        # Index by name for fast lookup
        self._by_name: Dict[str, VirtualPackage] = {
            pkg.name: pkg for pkg in self._packages.values()
        }

    # ── Core lookup ───────────────────────────────────────────────────────

    def get(self, name: str) -> Optional[VirtualPackage]:
        """Return the VirtualPackage with *name*, or None if not found."""
        return self._by_name.get(name)

    def list_packages(self, installed_only: bool = False) -> List[VirtualPackage]:
        """Return all packages, optionally filtered to installed only."""
        pkgs = list(self._packages.values())
        if installed_only:
            pkgs = [p for p in pkgs if p.installed]
        # Sort by name for deterministic output
        return sorted(pkgs, key=lambda p: p.name)

    def list_installed(self) -> List[VirtualPackage]:
        """Return installed packages sorted by name."""
        return self.list_packages(installed_only=True)

    # ── apt / apt-get command simulation ──────────────────────────────────

    def apt_query(self, package_name: str) -> Optional[VirtualPackage]:
        """Query the package database for *package_name* (apt-querysimilar semantic)."""
        pkg = self.get(package_name)
        if pkg is None:
            return None
        return VirtualPackage(
            name=pkg.name,
            version=pkg.version,
            architecture=pkg.architecture,
            installed=pkg.installed,
            dependencies=dict(pkg.dependencies),
            conffiles=pkg.conffiles,
            associated_service=pkg.associated_service,
            process_count=pkg.process_count,
            is_meta=pkg.is_meta,
            description=pkg.description,
        )

    def apt_list(self) -> str:
        """Return apt-style list output of all packages."""
        installed = self.list_installed()
        lines: List[str] = []
        for pkg in installed:
            lines.append(f"{pkg.name}/{pkg.architecture} {pkg.version}")
        if not lines:
            return "E: No packages installed."
        return "\n".join(lines)

    def apt_get_install(self, package_names: List[str]) -> List[Tuple[str, str]]:
        """Simulate `apt-get install <packages>`.

        Returns list of (package_name, status) tuples:
        - ('pkg_name', 'installed') on success
        - ('pkg_name', 'E: ...') on failure
        """
        results: List[Tuple[str, str]] = []
        for pkg_name in package_names:
            if not valid_package_name(pkg_name):
                results.append((pkg_name, f"E: Invalid package name '{pkg_name}'"))
                continue
            pkg = self.get(pkg_name)
            if pkg is None:
                results.append((pkg_name, f"E: Package '{pkg_name}' is not installed"))
                continue
            if pkg.installed:
                results.append((pkg_name, f"E: Package '{pkg_name}' is already installed"))
                continue
            # Check dependencies
            if not pkg.is_installable(self):
                # Compute missing deps
                missing = [
                    f"{dep}" for dep, ver in pkg.dependencies.items()
                    if not self.get(dep) or not self.get(dep).installed
                ]
                results.append((pkg_name, f"E: Dependency problem: {', '.join(missing)}"))
                continue
            # Install the package
            self._do_install(pkg)
            results.append((pkg_name, "installed"))
        return results

    def apt_get_remove(self, package_names: List[str], purge: bool = False) -> List[Tuple[str, str]]:
        """Simulate `apt-get remove/purge <packages>`.

        Returns list of (package_name, status) tuples.
        """
        results: List[Tuple[str, str]] = []
        for pkg_name in package_names:
            if not valid_package_name(pkg_name):
                results.append((pkg_name, f"E: Invalid package name '{pkg_name}'"))
                continue
            pkg = self.get(pkg_name)
            if pkg is None:
                results.append((pkg_name, f"E: Package '{pkg_name}' is not installed"))
                continue
            if not pkg.installed:
                results.append((pkg_name, f"E: Package '{pkg_name}' is not installed"))
                continue
            # Perform removal
            self._do_remove(pkg, purge=purge)
            results.append((pkg_name, "removed"))
        return results

    # ── dpkg command simulation ──────────────────────────────────────────

    def dpkg_query(self, package_name: str) -> Optional[VirtualPackage]:
        """Query the package database for *package_name* (dpkg -S semantic)."""
        return self.apt_query(package_name)

    def dpkg_status(self, package_name: str) -> str:
        """Return dpkg status string for *package_name*."""
        pkg = self.get(package_name)
        if pkg is None:
            return f"Package '{package_name}' is not installed and no info is available."
        if pkg.installed:
            return (
                f"Package: {pkg.name}\n"
                f"Version: {pkg.version}\n"
                f"Status: install ok installed\n"
            )
        return (
            f"Package: {pkg.name}\n"
            f"Version: {pkg.version}\n"
            f"Status: deinstall ok config-files\n"
        )

    # ── Internal installation/removal ─────────────────────────────────────

    def _do_install(self, pkg: VirtualPackage) -> None:
        """Install a package, updating all integrated VirtualOS state."""
        # Mark installed
        pkg.installed = True

        # Update associated service if any
        if pkg.associated_service:
            sm = get_service_manager()
            if sm is not None:
                svc = sm.get_service(pkg.associated_service)
                if svc is not None:
                    svc.state = "running"
                    if svc.pid is None:
                        # Create associated virtual process
                        pm = get_process_manager()
                        new_proc = pm.create(
                            ppid=1,
                            username="root",
                            cmdline=f"/usr/sbin/{pkg.associated_service}",
                        )
                        svc.pid = new_proc.pid
                        # Update network if service has listening ports
                        self._integrate_service_network(svc)

        # Create virtual filesystem entries for installed package
        fs = get_filesystem()
        if fs is not None:
            self._install_filesystem_entries(pkg, fs)

    def _do_remove(self, pkg: VirtualPackage, purge: bool = False) -> None:
        """Remove (or purge) a package, updating all integrated VirtualOS state."""
        # Mark not installed
        pkg.installed = False

        # Stop and remove associated service if any
        if pkg.associated_service:
            sm = get_service_manager()
            if sm is not None:
                svc = sm.get_service(pkg.associated_service)
                if svc is not None:
                    svc.state = "stopped"
                    svc.pid = None

        # Remove virtual filesystem entries for package
        fs = get_filesystem()
        if fs is not None:
            self._remove_filesystem_entries(pkg, fs, purge=purge)

    def _integrate_service_network(self, svc: Any) -> None:
        """Integrate a service's listening ports into the virtual network."""
        # This is handled by the service start/stop flow through network module
        pass

    def _install_filesystem_entries(self, pkg: VirtualPackage, fs: Any) -> None:
        """Create virtual filesystem entries associated with an installed package."""
        # Create /var/lib/<pkg> directory
        pkg_dir = f"/var/lib/{pkg.name}"
        fs.mkdir(pkg_dir, mode=0o755)

        # Create conffile entries if any
        # For baseline packages, create minimal marker files
        conffile_dir = f"/etc/{pkg.name}"
        if pkg.conffiles:
            fs.mkdir(conffile_dir, mode=0o755)
            for conffile in pkg.conffiles:
                marker_path = f"{conffile_dir}/{conffile}"
                fs.write_file(marker_path, f"# Configuration file for {pkg.name}\n", mode=0o644)
        else:
            # Default: create a marker file for the package
            fs.write_file(f"{pkg_dir}/installed", f"Package {pkg.name}-{pkg.version} installed\n", mode=0o644)

        # Create documentation stub
        doc_dir = f"/usr/share/doc/{pkg.name}"
        fs.mkdir(doc_dir, mode=0o755)
        fs.write_file(f"{doc_dir}/changelog.Debian.gz", "", mode=0o644)
        fs.write_file(f"{doc_dir}/copyright", f"# {pkg.name} license\n", mode=0o644)

    def _remove_filesystem_entries(self, pkg: VirtualPackage, fs: Any, purge: bool = False) -> None:
        """Remove virtual filesystem entries associated with a package removal."""
        pkg_dir = f"/var/lib/{pkg.name}"
        # Remove package directory and all contents
        fs.rmdir(pkg_dir)  # Will silently fail if not empty; that's OK

        # Remove conffile directory if not purge
        if not purge:
            conffile_dir = f"/etc/{pkg.name}"
            fs.rmdir(conffile_dir)

        # Remove documentation
        doc_dir = f"/usr/share/doc/{pkg.name}"
        fs.rmdir(doc_dir)

    # ── Persistence integration ──────────────────────────────────────────

    def snapshot(self) -> Dict[str, Any]:
        """Return a serializable snapshot of the package state."""
        packages_data: Dict[str, Dict[str, Any]] = {}
        for name, pkg in self._packages.items():
            packages_data[name] = {
                "name": pkg.name,
                "version": pkg.version,
                "architecture": pkg.architecture,
                "installed": pkg.installed,
                "dependencies": dict(pkg.dependencies),
                "conffiles": list(pkg.conffiles),
                "associated_service": pkg.associated_service,
                "process_count": pkg.process_count,
                "is_meta": pkg.is_meta,
                "description": pkg.description,
            }
        return {"packages": packages_data}

    def recover(self, data: Dict[str, Any]) -> None:
        """Recover package state from a snapshot dict."""
        packages_data = data.get("packages", {})
        for name, pkg_data in packages_data.items():
            pkg = VirtualPackage(
                name=pkg_data["name"],
                version=pkg_data.get("version", "0"),
                architecture=pkg_data.get("architecture", "all"),
                installed=pkg_data.get("installed", False),
                dependencies=pkg_data.get("dependencies", {}),
                conffiles=frozenset(pkg_data.get("conffiles", [])),
                associated_service=pkg_data.get("associated_service"),
                process_count=pkg_data.get("process_count", 0),
                is_meta=pkg_data.get("is_meta", False),
                description=pkg_data.get("description", ""),
            )
            self._packages[name] = pkg
            self._by_name[name] = pkg

    def get_installed_packages(self) -> List[str]:
        """Return list of installed package names (for persistence/telemetry)."""
        return [pkg.name for pkg in self.list_packages(installed_only=True)]


# ── Global instance ────────────────────────────────────────────────────────

_pm: PackageManager | None = None


def get_package_manager() -> PackageManager:
    """Return the global PackageManager, bootstrapping if necessary."""
    global _pm
    if _pm is None:
        _pm = PackageManager()
    return _pm


def get_package_manager_ptr() -> PackageManager | None:
    """Return the current PackageManager instance, or None if not yet set."""
    return _pm


def init_package_manager() -> PackageManager:
    """Explicitly initialise the global PackageManager."""
    global _pm
    _pm = PackageManager()
    return _pm