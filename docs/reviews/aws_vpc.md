# Review record: Amazon VPC security groups and network ACLs seed pack and authored exports

| | |
|---|---|
| Pack | `packs/vendors/aws_vpc` (pack_version 1), 55 mappings, JSON/YAML shape family read as records |
| Date | 2026-09-28 |
| Reviewer | Claude, delegated by the maintainer (as for the other seed packs) |
| Tasks | TODO M2.31 (seed pack, and the security-group reference case moved from M2.23), C.06 (authored exports vs AWS docs) |
| Result | Approved as `approved_by: [maintainer]` |

Same rule as every pack: **no quote, no default.** Every page below was read on 2026-09-28.

## 1. What the pack reads

The output of two AWS CLI commands, as JSON (the CLI's default) or YAML (`--output yaml`):

- `aws ec2 describe-security-groups`, which gives `{"SecurityGroups": [...]}`;
- `aws ec2 describe-network-acls`, which gives `{"NetworkAcls": [...]}`.

A VPC is one device, audited from one file holding both lists:

```
jq -s 'add' sg.json nacl.json > vpc.json
```

A file with only one of the two lists is read as **partial** (`records.sections`): the verdicts
stand only on what it shows (no PASS on the missing half). A file whose groups and ACLs name
more than one VPC is no single device's. It gets no hostname, and the report says which VPCs it
names (`identity.yaml`, `all_agree`).

The device role is `cloud_filter` (`pack.yaml`). Only two rules apply to cloud filters today:

- FILTER-PERMIT-ANY-01: no entry permits all traffic from anywhere to anywhere;
- REF-DANGLING-01: every reference points at something that exists.

Every other rule names the roles it covers (`applies_to: [router, switch, firewall, white_box]`):
an export of filters has no management plane, logging or AAA to judge. Exposure checks (SSH or
RDP open to the internet, the default security group) are M4.20/M4.21.

## 2. Vendor defaults (`defaults.yaml`)

| Default | Value | AWS's words | Source |
|---|---|---|---|
| `sg-unmatched-denied` | deny | "You can specify allow rules, but not deny rules." "When you first create a security group, it has no inbound rules. Therefore, no inbound traffic is allowed until you add inbound rules to the security group." | [Security group rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html) |
| `sg-empty-denies` | deny | the same, and "If your security group has no outbound rules, no outbound traffic is allowed." | same |
| `sg-order-irrelevant` (`curated`) | config | Model default: rules are allow-only, so their order can't change what they allow | same |
| `nacl-rule-number-order` | position | "Rules are evaluated starting with the lowest numbered rule. As soon as a rule matches traffic, it's applied regardless of any higher-numbered rule that might contradict it." NetworkAclEntry `ruleNumber`: "ACL entries are processed in ascending order by rule number." | [Network ACL rules](https://docs.aws.amazon.com/vpc/latest/userguide/nacl-rules.html), [NetworkAclEntry](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_NetworkAclEntry.html) |
| `nacl-unmatched-denied` | deny | "Each network ACL includes a default inbound rule and a default outbound rule whose rule number is an asterisk (*). These rules ensure that if a packet doesn't match any of the other rules, it's denied." "You can't delete a rule where the rule number is an asterisk." | [Custom network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/custom-network-acl.html) |
| `nacl-empty-denies` | deny | the asterisk rules can't be deleted, and "IPv4 and IPv6 traffic are evaluated separately. Therefore, none of the rules for IPv4 traffic apply to IPv6 traffic." | same |

The CLI prints the asterisk rules as entries 32767 (IPv4) and 32768 (IPv6), so they are also
read as ordinary deny entries ([describe-network-acls example](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-network-acls.html)).

## 3. Modelling decisions

- **Records.** A rule's facts are several fields of one object (`IpProtocol`, `FromPort`,
  `ToPort`), and a mapping reads one statement. So each list item's scalar fields, including
  those of objects inside it (`PortRange.From`), are one statement, `@` followed by each key and
  value in key order: `@ FromPort 22 IpProtocol tcp ToPort 22`. The lists inside an item
  (`IpRanges`, `UserIdGroupPairs`) follow beneath it. Security groups are named by `GroupId`
  and network ACLs by `NetworkAclId`; other items are numbered from 0.
- **A key given twice is refused.** JSON readers disagree on which of two equal keys counts
  (RFC 8259 leaves it open). A rule could hide behind the one Kasauti doesn't read, so the file
  is read line by line instead, with the reason, and nothing is judged PASS or FAIL.
- **Hostile exports.** Three AWS-shaped files join the hostile corpus (M2.07):
  - a group with very many rules;
  - an entry with very many fields;
  - one key given again and again.

  They exposed a quadratic repeated-key check and a slow composer (11 s per MiB). The
  document is now built from the parser's events (libyaml's parser where PyYAML has it), with
  nesting bounded as it arrives: about 4 s per MiB, linear.
- **A field no mapping expects makes the entry unknown.** The patterns name every field AWS
  documents. A record with another field doesn't match, so the entry is REVIEW, never PASS
  (test: an extra field in an `IpRanges` item). A network ACL entry that can't be read is not
  dropped: its direction and IP version are among its fields, so it counts as an entry of
  unknown effect in every ruleset (`policy/firstmatch.py`).
- **Security groups:**
  - Each rule in `IpPermissions` (inbound) or `IpPermissionsEgress` (outbound) is one permit
    entry in the ruleset `sg:<group>:ingress|egress`.
  - Its other end (the destination inbound, the source outbound) is the group's own instances.
    It is written `any`, as for an interface ACL, where everything behind the interface is
    what the filter protects.
  - The rules are always in force (`enabled: true`): IpPermission has no field that turns one
    off.
- **Services.** From [IpPermission](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IpPermission.html):
  - "Use `-1` to specify all protocols": read as `ip`.
  - TCP and UDP with ports: `tcp/22-22`.
  - ICMP and ICMPv6: read as `icmp` and `icmp6`.
  - Another protocol number: `ip-proto-<n>`, all of that protocol ("specifying `-1` or a
    protocol number other than tcp, udp, icmp, or icmpv6 allows traffic on all ports").
  - TCP or UDP without the ports the API requires: `tcp`, which the evaluator reads as "may
    name ports not read" (REVIEW, never all of TCP).
  - Network ACLs give protocol numbers only: "The protocol number. A value of "-1" means all
    protocols."
- **Addresses.**
  - `0.0.0.0/0` and `::/0` are `any`.
  - Every prefix is first reduced to the network it covers (the `network` transform), so a
    `/0` written with host bits (`10.1.2.3/0`) is `any` too. AWS canonicalises network ACL
    CIDRs ("the CIDR range is automatically modified to its canonical form"), and the pack
    doesn't rely on it.
  - A rule whose source is already every address stays a permit-any whatever else it names
    (`mapping/resolve.py`).
- **Network ACL entries:**
  - Ruleset `nacl:<acl>:ingress|egress:ipv4|ipv6`, since IPv4 and IPv6 are evaluated apart.
  - Position is the rule number; action `allow` is `permit`.
  - The other end is `any` (the subnet).
  - Always in force: NetworkAclEntry has no field that turns an entry off.
- **The default network ACL's rule 100 allows all traffic** ("A default network ACL is
  configured to allow all traffic to flow in and out of the subnets with which it is
  associated"). So a VPC that keeps it FAILs FILTER-PERMIT-ANY-01. So does a security group
  that keeps the default outbound allow-all. That is the rule's intent (SC-7(5): deny by
  default, allow by exception): a FAIL to explain, never a PASS to regret.

## 4. References between security groups (the case moved here from M2.23)

A rule's `UserIdGroupPairs` name other security groups. Each is a `ref` of kind
`security_group`:

| The pair | AWS's words | Result |
|---|---|---|
| names a group in the file | – | resolved, target `ObjectDef[security_group:<id>]` |
| carries `UserId` (the owner's account) but the group isn't in the file (another account, or an export filtered by VPC) | [UserIdGroupPair](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_UserIdGroupPair.html) `UserId`: "If the referenced security group is deleted, this value is not returned." [Delete a security group](https://docs.aws.amazon.com/vpc/latest/userguide/deleting-security-groups.html): "The security group can't be referenced by a rule in another security group." | resolved, with no target (`exists`): AWS's own answer says the group exists |
| has no `UserId` | the same sentence; [Stale security group rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html#vpc-stale-security-group-rules): "the rule is marked as stale when the referenced security group is deleted or the VPC peering connection is deleted" | dangling: REF-DANGLING-01 FAIL |

A group named as a source is the instances in it ("the rule affects all instances that are
associated with the security groups"), never every address: its extent is always narrow
(`NARROW_KINDS`). So all protocols from another group is no permit-any, and a stale reference
matches nothing.

**Prefix lists** (`PrefixListIds`) are a `ref` of kind `prefix_list`. A referenced list exists:
"To delete a prefix list, you must first remove any references to it in your resources"
([Work with customer-managed prefix lists](https://docs.aws.amazon.com/vpc/latest/userguide/work-with-cust-managed-prefix-lists.html)).
Its entries come from another command, `get-managed-prefix-list-entries`, not from these two
exports. So a rule naming one has sources of unknown extent: FILTER-PERMIT-ANY-01 is REVIEW for
it, and the finding names the line. To judge it, check the list's entries.

## 5. Identity

The device is the VPC: `hostname` is the `VpcId` that every security group and network ACL
record gives (`field: VpcId`). The `VpcId` of a peered group named in a rule is not read,
because it is another VPC. If the records name more than one VPC, no hostname is taken and the
report says which VPCs it found. An export has no OS version, model, serial number or
hardware; they are "not present".

## 6. Authored exports (C.06)

`datasets/authored/aws_vpc/hardened.json` and `weak.json` use the structure of the AWS CLI's
own examples ([describe-security-groups](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html),
[describe-network-acls](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-network-acls.html)):

- the same field names and nesting;
- `IcmpTypeCode {Code, Type}` and `PortRange {From, To}`;
- the asterisk rules as 32767 and 32768;
- `SecurityGroupArn` on one group.

IDs, accounts and addresses are illustrative. The account is AWS's documentation example,
111122223333. The weakness catalogue is in `datasets/SOURCES.md`.
