"""Policy loading, strict validation and evaluation.

Design rules (see SECURITY.md):
- Parsing is STRICT: an unknown key, a malformed rule or a duplicate user match
  aborts gateway startup. A typo in a policy file must never silently change
  what a user can reach.
- Evaluation is default-deny: an entity is accessible only if an explicit rule
  (entity / domain / area) grants it. `control` implies `read`.
- Area rules depend on the registry snapshot. If the snapshot is stale
  (upstream unreachable for too long), area rules evaluate to DENY — the
  gateway degrades by narrowing, never by widening.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

import yaml

from .model import Identity
from .registry import RegistryCache

log = logging.getLogger(__name__)

READ = "read"
CONTROL = "control"
_ACCESS_LEVELS = (READ, CONTROL)


class PolicyError(Exception):
    """A policy file is invalid. The gateway refuses to start."""


@dataclass(frozen=True)
class _RuleSet:
    """Access rules for one level (read or control)."""

    entities: frozenset[str] = frozenset()
    domains: frozenset[str] = frozenset()
    areas: frozenset[str] = frozenset()


@dataclass(frozen=True)
class UserPolicy:
    source_file: str
    match_user_id: str | None
    match_user_name: str | None
    read: _RuleSet = field(default_factory=_RuleSet)
    control: _RuleSet = field(default_factory=_RuleSet)
    default_dashboard: str | None = None
    allowed_dashboards: frozenset[str] = frozenset()

    def matches(self, identity: Identity) -> bool:
        if self.match_user_id is not None:
            return identity.user_id == self.match_user_id
        return identity.name == self.match_user_name

    @property
    def dashboards(self) -> frozenset[str]:
        extra = {self.default_dashboard} if self.default_dashboard else set()
        return self.allowed_dashboards | frozenset(extra)

    def to_editor_dict(self) -> dict:
        """Serialize back to the editable shape the admin UI uses."""

        def merged(kind: str) -> list[dict]:
            read = getattr(self.read, kind)
            control = getattr(self.control, kind)
            out = [{"id": i, "access": CONTROL} for i in sorted(control)]
            out += [{"id": i, "access": READ} for i in sorted(read - control)]
            return out

        return {
            "user": {"id": self.match_user_id, "name": self.match_user_name},
            "entities": merged("entities"),
            "domains": merged("domains"),
            "areas": merged("areas"),
            "dashboards": {
                "default": self.default_dashboard,
                "allowed": sorted(self.allowed_dashboards),
            },
        }


def _require_mapping(node: object, where: str) -> dict:
    if not isinstance(node, dict):
        raise PolicyError(f"{where}: expected a mapping, got {type(node).__name__}")
    return node


def _check_keys(node: dict, allowed: set[str], where: str) -> None:
    unknown = set(node) - allowed
    if unknown:
        raise PolicyError(
            f"{where}: unknown key(s) {sorted(unknown)} — refusing to guess "
            f"(allowed: {sorted(allowed)})"
        )


def _parse_rules(items: object, kind: str, where: str) -> list[tuple[str, str]]:
    """Return [(id, access)] for one of entities/areas/domains lists."""
    if items is None:
        return []
    if not isinstance(items, list):
        raise PolicyError(f"{where}: expected a list")
    out: list[tuple[str, str]] = []
    for i, item in enumerate(items):
        w = f"{where}[{i}]"
        node = _require_mapping(item, w)
        _check_keys(node, {"id", "access"}, w)
        ident = node.get("id")
        if not isinstance(ident, str) or not ident:
            raise PolicyError(f"{w}: 'id' must be a non-empty string")
        if kind == "entities" and "." not in ident:
            raise PolicyError(f"{w}: entity id {ident!r} must look like 'domain.object_id'")
        if kind == "domains" and "." in ident:
            raise PolicyError(
                f"{w}: domain {ident!r} must not contain '.' (did you mean an entity rule?)"
            )
        access = node.get("access", READ)
        if access not in _ACCESS_LEVELS:
            raise PolicyError(f"{w}: access must be one of {_ACCESS_LEVELS}, got {access!r}")
        out.append((ident, access))
    return out


def parse_policy(text: str, source_file: str) -> UserPolicy:
    try:
        root = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"{source_file}: YAML parse error: {exc}") from exc
    root = _require_mapping(root, source_file)
    _check_keys(root, {"user", "allow", "dashboards"}, source_file)

    user = _require_mapping(root.get("user"), f"{source_file}: user")
    _check_keys(user, {"id", "name"}, f"{source_file}: user")
    uid, uname = user.get("id"), user.get("name")
    if uid is not None and not isinstance(uid, str):
        raise PolicyError(f"{source_file}: user.id must be a string")
    if uname is not None and not isinstance(uname, str):
        raise PolicyError(f"{source_file}: user.name must be a string")
    if bool(uid) == bool(uname):
        raise PolicyError(
            f"{source_file}: user must set exactly one of 'id' or 'name' "
            f"(prefer 'id'; find it in the gateway log after a first attempt)"
        )

    allow = _require_mapping(root.get("allow", {}), f"{source_file}: allow")
    _check_keys(allow, {"entities", "areas", "domains"}, f"{source_file}: allow")

    read_ent, ctl_ent = set(), set()
    read_dom, ctl_dom = set(), set()
    read_area, ctl_area = set(), set()
    buckets = {
        "entities": (read_ent, ctl_ent),
        "domains": (read_dom, ctl_dom),
        "areas": (read_area, ctl_area),
    }
    for kind, (read_set, control_set) in buckets.items():
        for ident, access in _parse_rules(allow.get(kind), kind, f"{source_file}: allow.{kind}"):
            (control_set if access == CONTROL else read_set).add(ident)

    dash = _require_mapping(root.get("dashboards", {}), f"{source_file}: dashboards")
    _check_keys(dash, {"default", "allowed"}, f"{source_file}: dashboards")
    default_dash = dash.get("default")
    if default_dash is not None and not isinstance(default_dash, str):
        raise PolicyError(f"{source_file}: dashboards.default must be a string url_path")
    allowed_dash = dash.get("allowed", [])
    if not isinstance(allowed_dash, list) or not all(isinstance(d, str) for d in allowed_dash):
        raise PolicyError(f"{source_file}: dashboards.allowed must be a list of url_path strings")

    return UserPolicy(
        source_file=source_file,
        match_user_id=uid,
        match_user_name=uname,
        read=_RuleSet(frozenset(read_ent), frozenset(read_dom), frozenset(read_area)),
        control=_RuleSet(frozenset(ctl_ent), frozenset(ctl_dom), frozenset(ctl_area)),
        default_dashboard=default_dash,
        allowed_dashboards=frozenset(allowed_dash),
    )


class PolicyStore:
    """All user policies, loaded once at startup (restart to reload — deliberate:
    policy changes should be explicit operator actions, not hot file edits)."""

    def __init__(self, policies: list[UserPolicy]):
        self._policies = policies
        ids = [p.match_user_id for p in policies if p.match_user_id]
        names = [p.match_user_name for p in policies if p.match_user_name]
        for pool, label in ((ids, "user.id"), (names, "user.name")):
            dupes = {x for x in pool if pool.count(x) > 1}
            if dupes:
                raise PolicyError(f"duplicate {label} across policy files: {sorted(dupes)}")

    @classmethod
    def load_dir(cls, policy_dir: str) -> PolicyStore:
        if not os.path.isdir(policy_dir):
            raise PolicyError(f"policy dir {policy_dir!r} does not exist")
        policies = []
        for fn in sorted(os.listdir(policy_dir)):
            if not fn.endswith((".yaml", ".yml")) or fn.startswith("."):
                continue
            path = os.path.join(policy_dir, fn)
            with open(path, encoding="utf-8") as f:
                policies.append(parse_policy(f.read(), fn))
        log.info("loaded %d policy file(s) from %s", len(policies), policy_dir)
        if not policies:
            log.warning("no policies loaded — every user will be denied (fail closed)")
        return cls(policies)

    def find(self, identity: Identity) -> UserPolicy | None:
        by_id = [p for p in self._policies if p.match_user_id == identity.user_id]
        if by_id:
            return by_id[0]
        by_name = [
            p
            for p in self._policies
            if p.match_user_id is None and p.match_user_name == identity.name
        ]
        return by_name[0] if by_name else None

    def all_dashboards(self) -> frozenset[str]:
        out: set[str] = set()
        for p in self._policies:
            out |= p.dashboards
        return frozenset(out)

    def all(self) -> list[UserPolicy]:
        return list(self._policies)


class PolicyEvaluator:
    """Evaluates one user's policy against concrete entity ids."""

    def __init__(self, policy: UserPolicy, registry: RegistryCache):
        self._p = policy
        self._reg = registry

    @property
    def policy(self) -> UserPolicy:
        return self._p

    def _match(self, rules: _RuleSet, entity_id: str) -> bool:
        if entity_id in rules.entities:
            return True
        domain = entity_id.split(".", 1)[0]
        if domain in rules.domains:
            return True
        if rules.areas:
            # Area rules fail closed when the registry is stale/unavailable.
            area = self._reg.area_of(entity_id)
            if area is not None and area in rules.areas:
                return True
        return False

    def allowed_control(self, entity_id: str) -> bool:
        return self._match(self._p.control, entity_id)

    def allowed_read(self, entity_id: str) -> bool:
        # control implies read
        return self.allowed_control(entity_id) or self._match(self._p.read, entity_id)

    def allowed_area_ids(self) -> set[str]:
        """Area ids that contain at least one entity the user may read."""
        areas = {self._reg.area_of(e) for e in self.enumerable_read_entities()}
        areas.discard(None)
        return areas  # type: ignore[return-value]

    def allowed_device_ids(self) -> set[str]:
        """Device ids that own at least one entity the user may read."""
        devices = {self._reg.device_of(e) for e in self.enumerable_read_entities()}
        devices.discard(None)
        return devices  # type: ignore[return-value]

    def enumerable_read_entities(self) -> list[str]:
        """Concrete entity ids for subscribe_entities rewriting.

        Static entity rules always count. Domain/area rules are expanded via the
        registry snapshot; when the registry is stale, expansion shrinks to the
        static list (fail closed — narrower, never wider).
        """
        out = set(self._p.read.entities) | set(self._p.control.entities)
        domains = self._p.read.domains | self._p.control.domains
        areas = self._p.read.areas | self._p.control.areas
        if domains or areas:
            out |= self._reg.entities_matching(domains=domains, areas=areas)
        return sorted(out)

    def filter_states(self, states: list) -> list:
        """Filter a get_states-style list of state dicts."""
        keep = []
        for s in states:
            eid = s.get("entity_id") if isinstance(s, dict) else None
            if isinstance(eid, str) and self.allowed_read(eid):
                keep.append(s)
        return keep
