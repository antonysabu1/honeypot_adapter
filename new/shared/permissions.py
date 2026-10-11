"""POSIX-style access control for the virtual filesystem.

Separation of concerns: ``FakeFilesystem`` owns inode *data* (mode/uid/gid and
content); this module owns the *policy* of whether an operation is allowed.  The
identity evaluated here is always the **virtual** one, derived from
UserDatabase/GroupDatabase by login name — the host process's uid/gid is never
consulted, and no host filesystem call is made.

Deliberate subset (documented, consistent, and intentionally not exhaustive):

* Read ``R``, write ``W``, execute ``X`` bits for owner / group / other.
* An identity matches owner by uid, else group if the inode gid is the primary
  or a supplementary group, else other.
* Reaching a path requires ``X`` (search) on every ancestor directory.
* Listing a directory needs ``R`` (names) and ``X`` (to stat its entries).
* Creating or removing an entry needs ``W`` and ``X`` on the parent directory
  (the nearest existing ancestor when intermediate ones do not exist yet, as
  with ``mkdir -p``); overwriting an existing file additionally needs ``W`` on
  that file.
* The sticky bit (``S_ISVTX``) on a directory restricts removal/rename to the
  file's owner, the directory's owner, or root.
* ``chmod``: owner or root.  ``chown`` uid: root only.  ``chgrp``/``chown`` gid:
  root, or the file's owner changing to a group they belong to.
* **Root (uid 0) bypasses all of the above** (models CAP_DAC_OVERRIDE).  An
  accepted-but-unknown login is modeled as root, matching ``id``'s existing
  fallback and the honeypot's "always a root shell" presentation.
"""

from __future__ import annotations

from dataclasses import dataclass

R, W, X = 4, 2, 1
STICKY = 0o1000


@dataclass(frozen=True)
class Identity:
    """A process' virtual credentials, derived once per command.

    Not stored state: it is a view computed from the authoritative databases, so
    it cannot drift from ``/etc/passwd`` and ``/etc/group``.
    """

    uid: int
    gid: int
    groups: frozenset[int]
    name: str

    @property
    def is_root(self) -> bool:
        return self.uid == 0


def identity_for(fs, username: str) -> Identity:
    """Effective identity for a login name, from the virtual databases."""
    u = fs.users.get(username)
    if u is None:
        # Unknown login (honeypot accepts anyone): root, as `id` already reports.
        return Identity(uid=0, gid=0, groups=frozenset({0}), name=username)
    gids = {u.gid}
    for gname in fs.groups.memberships_for(username):
        g = fs.groups.get(gname)
        if g is not None:
            gids.add(g.gid)
    return Identity(uid=u.uid, gid=u.gid, groups=frozenset(gids), name=username)


def _grants(mode: int, ident: Identity, uid: int, gid: int, want: int) -> bool:
    """True when the class the identity falls into holds *all* bits in ``want``."""
    if ident.uid == uid:
        shift = 6
    elif gid in ident.groups:
        shift = 3
    else:
        shift = 0
    return ((mode >> shift) & 0o7 & want) == want


def traverse(fs, path: str, ident: Identity) -> bool:
    """``X`` on every ancestor directory: search permission along the path."""
    if ident.is_root:
        return True
    chain = fs.resolve_chain(path)
    if chain is None:
        return False
    for node in chain[:-1]:
        if not node.is_dir:
            return False
        if not _grants(node.mode, ident, node.uid, node.gid, X):
            return False
    return True


def check(fs, path: str, ident: Identity, want: int) -> bool:
    """Allowed to perform ``want`` (a bitmask of R/W/X) on ``path``.

    Ancestors must grant ``X``; the target itself must grant ``want``.
    """
    if ident.is_root:
        return True
    chain = fs.resolve_chain(path)
    if chain is None:
        return False
    for node in chain[:-1]:
        if not node.is_dir:
            return False
        if not _grants(node.mode, ident, node.uid, node.gid, X):
            return False
    target = chain[-1]
    return _grants(target.mode, ident, target.uid, target.gid, want)


def can_list_dir(fs, path: str, ident: Identity) -> bool:
    """A directory listing needs names (R) and entry metadata (X)."""
    return check(fs, path, ident, R | X)


def can_create(fs, path: str, ident: Identity) -> bool:
    """May create a new entry called ``path``: W+X on the directory that would
    receive it.  When intermediate directories do not exist yet (``mkdir -p``)
    the nearest existing ancestor is the one that grants, exactly the directory
    whose write permission makes the creation possible.
    """
    if ident.is_root:
        return True
    parent = fs.dirname_of(path) or "/"
    while fs.resolve(parent) is None:
        up = fs.dirname_of(parent) or "/"
        if up == parent:
            return False
        parent = up
    return check(fs, parent, ident, W | X)


def can_write(fs, path: str, ident: Identity) -> bool:
    """May create ``path`` or overwrite it: ``can_create`` plus W on the file
    itself when it already exists (writing never bypasses the file's own mode)."""
    if ident.is_root:
        return True
    node = fs.resolve(path)
    if node is not None and not _grants(node.mode, ident, node.uid, node.gid, W):
        return False
    return can_create(fs, path, ident)


def can_unlink(fs, path: str, ident: Identity) -> bool:
    """May remove/rename the entry at ``path`` (W+X parent, plus sticky rule)."""
    if ident.is_root:
        return True
    parent = fs.parent_of(path)
    if parent is None:
        return False
    parent_inode, _name = parent
    parent_path = fs.dirname_of(path) or "/"
    if not check(fs, parent_path, ident, W | X):
        return False
    if parent_inode.mode & STICKY:
        target = fs.resolve(path)
        if target is not None and ident.uid not in (target.uid, parent_inode.uid):
            return False
    return True


def can_chmod(fs, path: str, ident: Identity) -> bool:
    if ident.is_root:
        return True
    if not traverse(fs, path, ident):
        return False
    node = fs.resolve(path)
    return node is not None and node.uid == ident.uid


def can_administer(ident: Identity) -> bool:
    """May change the virtual account databases (``/etc/passwd``, ``/etc/group``)
    and create/remove home directories.

    Account authority is a privileged operation: only virtual root may.  The
    honeypot presents its accepted-anyone shell as root, so this is the same
    identity that already bypasses file permissions.
    """
    return ident.is_root


def can_chown(fs, path: str, ident: Identity, *, new_uid: int | None,
              new_gid: int | None) -> bool:
    """Root may change owner and group; a non-root owner may only chgrp to a
    group they belong to (never change the uid)."""
    if not traverse(fs, path, ident):
        return False
    node = fs.resolve(path)
    if node is None:
        return False
    if ident.is_root:
        return True
    if new_uid is not None:
        return False
    if new_gid is not None and new_gid not in ident.groups:
        return False
    return node.uid == ident.uid
