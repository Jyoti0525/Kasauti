"""SBM entities (PLAN §8.1).

Security properties live at different scopes (device, vty range, interface, user, rule), so the
SBM is a small entity model rather than a flat dictionary. Every attribute is a :class:`Fact`.

Each entity has a ``type`` discriminator and a ``key`` that is unique within its type
(``"vty 0-4"``, ``"GigabitEthernet0/1"``, ``"telnet"``). Singletons use a fixed key.

Deviations from the §8.1 table, each needed by other parts of the plan:

* ``LoggingPolicy`` holds the device-wide logging flags (timestamps, admin_logged,
  config_change_logged) that §8.1 lists beside ``LogTarget``; they aren't per-target.
* ``TimePolicy`` holds device-wide NTP settings. Whether authentication is *enforced* (Cisco
  ``ntp authenticate``, OpenConfig ``enable-ntp-auth``) is not a property of one server.
* ``ObjectDef`` holds named address/service objects, groups and ACLs, the targets of the
  ``ref`` primitive and the reference resolver (§9.1, v5.1).
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from kasauti.sbm.facts import Evidence, Fact, StrSet

BoolFact = Fact[bool]
IntFact = Fact[int]
StrFact = Fact[str]
SetFact = Fact[StrSet]


class Entity(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    key: str = Field(min_length=1)
    evidence: tuple[Evidence, ...] = ()
    """The statements that opened or named this entity (``line vty 0 4``), so a finding about
    it can point at where it is, even when the attribute in question was never set."""

    @property
    def entity_id(self) -> str:
        """Stable identifier used in findings and evidence, e.g. ``MgmtSession[vty 0-4]``."""
        return f"{type(self).__name__}[{self.key}]"


# --- Device and management plane ------------------------------------------------------------


class Device(Entity):
    type: Literal["Device"] = "Device"
    key: str = "device"
    hostname: StrFact = StrFact()
    vendor: StrFact = StrFact()
    os_family: StrFact = StrFact()
    os_version: StrFact = StrFact()
    model: StrFact = StrFact()
    serial: StrFact = StrFact()
    hardware: StrFact = StrFact()
    role: StrFact = StrFact()
    """router | switch | firewall | cloud_filter | white_box (inferred, overridable; §7)."""


class MgmtService(Entity):
    """A service the device itself offers on the network; ``key`` is its kind. Management
    services (ssh, telnet, http, https, snmp, netconf) and the legacy ones hardening guides
    switch off (pad, finger, bootp, tcp-small-servers, udp-small-servers)."""

    type: Literal["MgmtService"] = "MgmtService"
    enabled: BoolFact = BoolFact()
    version: StrFact = StrFact()
    access_filter: StrFact = StrFact()
    """ACL restricting who may reach the service (Cisco ``ip http access-class``), 0.3."""
    ciphers: SetFact = SetFact()
    macs: SetFact = SetFact()
    kex: SetFact = SetFact()


class MgmtSession(Entity):
    """A way in: console, vty range, web or API session."""

    type: Literal["MgmtSession"] = "MgmtSession"
    kind: StrFact = StrFact()
    """console | vty | web | api"""
    range: StrFact = StrFact()
    transport: SetFact = SetFact()
    access_filter: StrFact = StrFact()
    """Name of the ACL/object restricting access; resolved to ``ObjectDef`` by the resolver."""
    idle_timeout_s: IntFact = IntFact()
    auth_method: StrFact = StrFact()


class Interface(Entity):
    type: Literal["Interface"] = "Interface"
    description: StrFact = StrFact()
    """Free text written by the admin (0.3). Used only to recognise an interface's role
    (``WAN uplink``); like banners, never fed to any AI signal (PLAN §17)."""
    zone: StrFact = StrFact()
    role: StrFact = StrFact()
    """untrusted | trusted | mgmt (inferred + overridable; drives exposure, §12.7)."""
    admin_up: BoolFact = BoolFact()
    mgmt_protocols: SetFact = SetFact()
    proxy_arp: BoolFact = BoolFact()
    """The interface answers ARP on behalf of other hosts (0.3)."""
    filters_in: SetFact = SetFact()
    filters_out: SetFact = SetFact()


# --- AAA ------------------------------------------------------------------------------------


class LocalUser(Entity):
    type: Literal["LocalUser"] = "LocalUser"
    privilege: IntFact = IntFact()
    hash_type: StrFact = StrFact()
    """Kind of stored secret (e.g. cisco-type-7, cisco-type-9, sha512); never the secret."""


class AuthServer(Entity):
    type: Literal["AuthServer"] = "AuthServer"
    kind: StrFact = StrFact()
    """tacacs | radius | ldap"""
    host: StrFact = StrFact()
    key_present: BoolFact = BoolFact()


class PasswordPolicy(Entity):
    type: Literal["PasswordPolicy"] = "PasswordPolicy"
    key: str = "password-policy"
    min_length: IntFact = IntFact()
    complexity_required: BoolFact = BoolFact()
    reversible_encryption_blocked: BoolFact = BoolFact()
    """The device refuses to store passwords in a reversible form (a strong-hash-only policy).
    Not Cisco ``service password-encryption``, which *applies* reversible type 7."""
    cleartext_passwords_encrypted: BoolFact = BoolFact()
    """Passwords that would otherwise sit in the configuration in clear text are encrypted
    (Cisco ``service password-encryption``, type 7). A baseline, not strong protection (0.3)."""
    max_age_days: IntFact = IntFact()
    enforced: BoolFact = BoolFact()
    """The policy is switched on, on platforms where it has its own switch (FortiOS
    ``config system password-policy`` / ``set status enable``). Absent where stating a
    minimum is what enforces it (Cisco, Junos, EOS) (0.5)."""


class LockoutPolicy(Entity):
    type: Literal["LockoutPolicy"] = "LockoutPolicy"
    key: str = "lockout-policy"
    max_attempts: IntFact = IntFact()
    lockout_s: IntFact = IntFact()


# --- Logging and time ----------------------------------------------------------------------


class LogTarget(Entity):
    type: Literal["LogTarget"] = "LogTarget"
    host: StrFact = StrFact()
    transport: StrFact = StrFact()
    """udp | tcp | tls"""
    severity: StrFact = StrFact()
    enabled: BoolFact = BoolFact()
    """The target is switched on, on platforms where a configured server can be off (FortiOS
    ``config log syslogd setting`` / ``set status enable``). Absent where naming a host is
    what turns it on (0.5)."""


class LoggingPolicy(Entity):
    type: Literal["LoggingPolicy"] = "LoggingPolicy"
    key: str = "logging-policy"
    timestamps: BoolFact = BoolFact()
    """Log messages carry the date and time (not just uptime), so events can be correlated."""
    admin_logged: BoolFact = BoolFact()
    config_change_logged: BoolFact = BoolFact()


class TimeSource(Entity):
    type: Literal["TimeSource"] = "TimeSource"
    host: StrFact = StrFact()
    authenticated: BoolFact = BoolFact()
    """A key is configured for this server. Only effective if ``TimePolicy.auth_enforced``."""


class TimePolicy(Entity):
    type: Literal["TimePolicy"] = "TimePolicy"
    key: str = "time-policy"
    auth_enforced: BoolFact = BoolFact()
    """The device rejects time from unauthenticated sources (``ntp authenticate``)."""


# --- SNMP -----------------------------------------------------------------------------------


class SnmpCommunity(Entity):
    """``key`` is an ordinal (``community-1``), never the community string, which is a secret."""

    type: Literal["SnmpCommunity"] = "SnmpCommunity"
    access: StrFact = StrFact()
    """ro | rw"""
    filter: StrFact = StrFact()
    is_well_known: BoolFact = BoolFact()
    """True for guessable strings such as ``public``/``private`` (checked before masking)."""


class SnmpUser(Entity):
    type: Literal["SnmpUser"] = "SnmpUser"
    auth: StrFact = StrFact()
    """none | md5 | sha | sha-256 | …"""
    priv: StrFact = StrFact()
    """none | des | aes-128 | …"""


# --- Crypto, filtering, objects -------------------------------------------------------------


class CryptoProfile(Entity):
    type: Literal["CryptoProfile"] = "CryptoProfile"
    purpose: StrFact = StrFact()
    """ike | ipsec | ssh | tls"""
    algorithms: SetFact = SetFact()
    dh_groups: SetFact = SetFact()
    lifetime_s: IntFact = IntFact()


class FilterRule(Entity):
    """One entry of an ordered ruleset (ACL, firewall policy, security group, NACL)."""

    type: Literal["FilterRule"] = "FilterRule"
    ruleset: StrFact = StrFact()
    position: IntFact = IntFact()
    name: StrFact = StrFact()
    src: SetFact = SetFact()
    dst: SetFact = SetFact()
    service: SetFact = SetFact()
    action: StrFact = StrFact()
    """permit | deny | drop | reject"""
    log: BoolFact = BoolFact()
    enabled: BoolFact = BoolFact()
    zone_from: StrFact = StrFact()
    zone_to: StrFact = StrFact()


class ObjectDef(Entity):
    """A named object that other statements reference; ``key`` is ``<kind>:<name>``."""

    type: Literal["ObjectDef"] = "ObjectDef"
    kind: StrFact = StrFact()
    """address | address_group | service | service_group | acl"""
    members: SetFact = SetFact()
    expanded: SetFact = SetFact()
    """Groups only: members after recursive expansion of nested groups (0.4). Unknown if the
    nesting has a cycle or names an object that doesn't exist."""


class Reference(Entity):
    """One statement pointing at another named thing (PLAN §9.1 ``ref``, 0.4): an ACL on a vty
    line, an address group in a policy. Created by the reference resolver, so dangling
    references and "which sources does this ACL permit?" are facts rules can judge.
    ``key`` is ``<source entity>.<attribute> -> <name>``."""

    type: Literal["Reference"] = "Reference"
    source: StrFact = StrFact()
    """The referring entity, e.g. ``MgmtSession[vty 0-4]``."""
    attribute: StrFact = StrFact()
    """``MgmtSession.access_filter``"""
    target_kind: StrFact = StrFact()
    """acl | address | address_group | service | service_group | any_object"""
    name: StrFact = StrFact()
    resolved: BoolFact = BoolFact()
    target: StrFact = StrFact()
    """The entity it resolves to, e.g. ``ObjectDef[acl:MGMT-ACL]``."""
    permits_any: BoolFact = BoolFact()
    """ACL targets only: some entry permits traffic from any source."""


# --- Domain-specific ------------------------------------------------------------------------


class Banner(Entity):
    """``key`` is the banner kind (motd, login, exec). Banner text is attacker-writable free
    text: it is stored for display only and never fed to any AI signal (PLAN §17)."""

    type: Literal["Banner"] = "Banner"
    present: BoolFact = BoolFact()
    text: StrFact = StrFact()


class RoutingAuth(Entity):
    """``key`` is ``<protocol>:<scope>``, e.g. ``ospf:area 0`` or ``bgp:neighbor 192.0.2.1``."""

    type: Literal["RoutingAuth"] = "RoutingAuth"
    protocol: StrFact = StrFact()
    scope: StrFact = StrFact()
    method: StrFact = StrFact()
    """none | plaintext | md5 | sha | keychain"""


class L2Port(Entity):
    type: Literal["L2Port"] = "L2Port"
    mode: StrFact = StrFact()
    """access | trunk"""
    port_security: BoolFact = BoolFact()
    bpdu_guard: BoolFact = BoolFact()
    native_vlan: IntFact = IntFact()
    storm_control: BoolFact = BoolFact()


class Tunnel(Entity):
    type: Literal["Tunnel"] = "Tunnel"
    kind: StrFact = StrFact()
    """ipsec | gre | ssl-vpn"""
    peer: StrFact = StrFact()
    crypto_profile: StrFact = StrFact()


AnyEntity = Annotated[
    Device
    | MgmtService
    | MgmtSession
    | Interface
    | LocalUser
    | AuthServer
    | PasswordPolicy
    | LockoutPolicy
    | LogTarget
    | LoggingPolicy
    | TimeSource
    | TimePolicy
    | SnmpCommunity
    | SnmpUser
    | CryptoProfile
    | FilterRule
    | ObjectDef
    | Reference
    | Banner
    | RoutingAuth
    | L2Port
    | Tunnel,
    Field(discriminator="type"),
]

ENTITY_TYPES: dict[str, type[Entity]] = {
    cls.__name__: cls
    for cls in (
        Device,
        MgmtService,
        MgmtSession,
        Interface,
        LocalUser,
        AuthServer,
        PasswordPolicy,
        LockoutPolicy,
        LogTarget,
        LoggingPolicy,
        TimeSource,
        TimePolicy,
        SnmpCommunity,
        SnmpUser,
        CryptoProfile,
        FilterRule,
        ObjectDef,
        Reference,
        Banner,
        RoutingAuth,
        L2Port,
        Tunnel,
    )
}

SINGLETON_TYPES = frozenset(
    {"Device", "PasswordPolicy", "LockoutPolicy", "LoggingPolicy", "TimePolicy"}
)


def attribute_names(entity_type: str) -> tuple[str, ...]:
    """The fact-valued attributes of an entity type, in declaration order."""
    cls = ENTITY_TYPES[entity_type]
    return tuple(
        name
        for name, field in cls.model_fields.items()
        if name not in ("type", "key", "evidence") and _is_fact(field.annotation)
    )


def _is_fact(annotation: Any) -> bool:
    return isinstance(annotation, type) and issubclass(annotation, Fact)
