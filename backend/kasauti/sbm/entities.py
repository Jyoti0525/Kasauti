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
* ``AuthPolicy`` holds which methods administrator logins use (OpenConfig
  ``authentication-method``): a TACACS+ server that no login uses protects nothing (0.8).
* ``ObjectDef`` holds named address/service objects, groups and ACLs, the targets of the
  ``ref`` primitive and the reference resolver (§9.1, v5.1).
* ``Ruleset`` holds what an ordered list of filter entries does as a whole: its order, what
  happens to traffic no entry matches, and whether it guards the device itself (0.9). These
  are quoted vendor facts, never assumed: Cisco's access lists end in an implicit deny,
  FortiOS local-in policies don't.
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
    permitted_sources: SetFact = SetFact()
    """Addresses the service accepts connections from; ``any`` means anywhere (PAN-OS
    ``permitted-ip``, where an empty list means any address). Absent where an ACL
    (``access_filter``) or per-account sources restrict access instead (0.7)."""
    port: IntFact = IntFact()
    """The TCP port the service listens on (FortiOS ``admin-sport``), so a filter naming ports
    can be matched against it (0.9)."""
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
    login_methods: SetFact = SetFact()
    """What logins on this line are checked against, where the line names its own method list
    (Cisco ``login authentication VTY-LOGIN``), expanded like ``AuthPolicy.login_methods``.
    Absent where the line uses the device default (0.9)."""


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
    mgmt_permitted_sources: SetFact = SetFact()
    """Addresses the interface accepts management connections from; ``any`` means anywhere
    (a PAN-OS interface management profile's ``permitted-ip``, where an empty list means no
    restriction). Absent where the platform restricts management per service or account
    instead (0.8)."""
    mgmt_protocols_v6: SetFact = SetFact()
    """Management protocols the interface offers over IPv6, where the platform lists them
    separately (FortiOS ``ip6-allowaccess``). They are in ``mgmt_protocols`` too (0.9)."""
    mgmt_restricted: SetFact = SetFact()
    """Management protocols that a filter guarding the device itself (FortiOS local-in
    policies) blocks on this interface for every source outside the ones it lists, on every IP
    version the interface offers them. Computed by the resolver's first-match evaluation (0.9)."""
    proxy_arp: BoolFact = BoolFact()
    """The interface answers ARP on behalf of other hosts (0.3)."""
    filters_in: SetFact = SetFact()
    filters_out: SetFact = SetFact()


# --- AAA ------------------------------------------------------------------------------------


class LocalUser(Entity):
    type: Literal["LocalUser"] = "LocalUser"
    privilege: IntFact = IntFact()
    hash_type: StrFact = StrFact()
    """Kind of stored secret (e.g. cisco-type-7, cisco-type-9, sha512); never the secret.
    ``remote``: the account keeps no password on the device and logs in against a remote
    server (FortiOS ``set remote-auth enable``)."""
    permitted_sources: SetFact = SetFact()
    """Addresses this account may log in from; ``any`` means anywhere (FortiOS ``trusthost1``
    to ``trusthost10``). Absent where the platform restricts sources per line or service
    instead (Cisco ``access-class``), not per account (0.6)."""
    permitted_sources_v6: SetFact = SetFact()
    """The IPv6 sources, on platforms that keep them apart (FortiOS ``ip6-trusthost1`` to
    ``ip6-trusthost10``, each defaulting to ``::/0``) (0.6)."""


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


class AuthPolicy(Entity):
    """How administrator logins are checked, device-wide (0.8)."""

    type: Literal["AuthPolicy"] = "AuthPolicy"
    key: str = "auth-policy"
    login_methods: SetFact = SetFact()
    """What administrator logins are checked against: ``tacacs``, ``radius``, ``ldap``,
    ``local`` (OpenConfig ``authentication-method``). A server group, user group or
    authentication profile counts as the kinds of server it contains, so a central server
    that is configured but that no login uses isn't in this set."""


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
    enabled: BoolFact = BoolFact()
    """The device takes time from this source, on platforms where a known source can be unused
    (FortiOS uses FortiGuard's servers unless ``set type custom``). Absent where listing a
    server is what uses it (0.6)."""


class TimePolicy(Entity):
    type: Literal["TimePolicy"] = "TimePolicy"
    key: str = "time-policy"
    auth_enforced: BoolFact = BoolFact()
    """The device rejects time from unauthenticated sources (``ntp authenticate``)."""
    sync_enabled: BoolFact = BoolFact()
    """The device sets its clock from its time sources at all (FortiOS ``set ntpsync enable``,
    OpenConfig ``ntp/config/enabled``). Absent where configuring a server is what turns
    synchronisation on (0.6)."""


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
    applications: SetFact = SetFact()
    """Applications the entry matches, on platforms that match by application as well as by
    port (PAN-OS ``application``); ``any`` means every application. Absent where entries match
    by protocol and port only (0.7)."""
    interfaces: SetFact = SetFact()
    """Incoming interfaces the entry applies to; ``any`` means all (FortiOS local-in ``intf``).
    Absent where the ruleset is bound to interfaces elsewhere (an ACL applied by name) (0.9)."""
    negated: SetFact = SetFact()
    """Which of ``src``, ``dst``, ``service`` the entry matches the complement of (FortiOS
    ``srcaddr-negate``) (0.9)."""
    narrowed: BoolFact = BoolFact()
    """The entry also matches on something the SBM doesn't model (a schedule other than
    always, Internet-service sources), so it matches only part of the traffic its addresses
    and services name. A narrowed deny never counts as blocking everything (0.9)."""


class Ruleset(Entity):
    """An ordered list of filter entries as a whole; ``key`` is the name the entries give in
    ``FilterRule.ruleset``. The mapper creates one for every ruleset that has entries and every
    ACL object, and quoted vendor defaults say how it behaves (0.9)."""

    type: Literal["Ruleset"] = "Ruleset"
    order: StrFact = StrFact()
    """``position``: entries are evaluated by position number (NACL rule numbers);
    ``config``: in the order the configuration lists them (FortiOS, where the policy ID is not
    the order). Absent: position numbers are used where every entry has one and they agree
    with the configuration's order; otherwise the order can't be told."""
    unmatched: StrFact = StrFact()
    """``permit`` | ``deny``: what happens to traffic no entry matches."""
    when_empty: StrFact = StrFact()
    """``permit`` | ``deny``: what the ruleset does when it has no entries at all, where that
    differs from ``unmatched`` (Cisco: "an empty access list ... permits all traffic")."""
    applies_to: StrFact = StrFact()
    """``device``: the ruleset guards traffic addressed to the device itself, on the
    interfaces its entries name (FortiOS local-in policies). Absent: it applies where it is
    referenced (an ACL on a vty line or an interface)."""
    family: StrFact = StrFact()
    """``ipv4`` | ``ipv6``: the IP version a device ruleset guards."""


class ObjectDef(Entity):
    """A named object that other statements reference; ``key`` is ``<kind>:<name>``."""

    type: Literal["ObjectDef"] = "ObjectDef"
    kind: StrFact = StrFact()
    """address | address_group | service | service_group | acl | mgmt_profile | server_group |
    user_group | auth_server | auth_profile | login_list"""
    members: SetFact = SetFact()
    expanded: SetFact = SetFact()
    """Groups only: members after recursive expansion of nested groups (0.4). Unknown if the
    nesting has a cycle or names an object that doesn't exist. A user group's leaves are
    authentication servers, so it expands to their kinds (``tacacs``), not their names (0.8)."""
    permitted_sources: SetFact = SetFact()
    """Management profiles only: the addresses the profile accepts connections from (0.8)."""
    destinations: SetFact = SetFact()
    """Service objects only: the destinations the service is limited to (FortiOS ``set
    iprange`` / ``set fqdn``); ``any`` or absent means no limit (0.8)."""


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
    | AuthPolicy
    | LockoutPolicy
    | LogTarget
    | LoggingPolicy
    | TimeSource
    | TimePolicy
    | SnmpCommunity
    | SnmpUser
    | CryptoProfile
    | FilterRule
    | Ruleset
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
        AuthPolicy,
        LockoutPolicy,
        LogTarget,
        LoggingPolicy,
        TimeSource,
        TimePolicy,
        SnmpCommunity,
        SnmpUser,
        CryptoProfile,
        FilterRule,
        Ruleset,
        ObjectDef,
        Reference,
        Banner,
        RoutingAuth,
        L2Port,
        Tunnel,
    )
}

SINGLETON_TYPES = frozenset(
    {"Device", "PasswordPolicy", "AuthPolicy", "LockoutPolicy", "LoggingPolicy", "TimePolicy"}
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
