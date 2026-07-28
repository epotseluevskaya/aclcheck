#!/usr/bin/env python3
"""
aclcheck.py - Enumerate outbound AD write permissions for a user.

Tested for the APIs used by Impacket 0.13.x + ldap3.

This tool is read-only. It:
  * authenticates with Impacket's init_ldap_session()
  * resolves the target user's SID
  * resolves transitive group memberships with LDAP_MATCHING_RULE_IN_CHAIN
  * enumerates AD objects with paged LDAP searches
  * requests each object's owner and DACL (SDFlags 0x05)
  * reports matching allow ACEs for the user or any resolved group
  * emits a small BloodHound-style set of control edges by default

Important:
  This is an ACE enumerator, not a complete Windows AuthZ engine. It does not
  fully calculate effective access across deny ACE ordering, conditional ACEs,
  claims, SIDHistory, token restrictions, or every inheritance edge case.
"""

import argparse
import csv
import logging
import sys
import traceback
from typing import Dict, Iterable, List, Optional, Set, Tuple

import ldap3
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import init_ldap_session, parse_identity
from impacket.ldap import ldaptypes
from impacket.msada_guids import EXTENDED_RIGHTS, SCHEMA_OBJECTS
from impacket.uuid import bin_to_string


MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"

# Access-mask bits relevant to outbound control.
RIGHTS = {
    "GenericAll": 0x10000000,
    "GenericWrite": 0x40000000,
    "WriteDACL": 0x00040000,
    "WriteOwner": 0x00080000,
    "WriteProperty": 0x00000020,
    "ControlAccess": 0x00000100,
    "Self": 0x00000008,
}

# Object/extended-right GUIDs used for the small BloodHound-like edge set.
GUID_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
GUID_RESET_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
GUID_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GUID_GET_CHANGES_FILTERED = "89e95b76-444d-4c62-991a-0facbeda640c"
GUID_SERVICE_PRINCIPAL_NAME = "bf967a86-0de6-11d0-a285-00aa003049e2"
GUID_KEY_CREDENTIAL_LINK = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
GUID_ALLOWED_TO_ACT = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"
GUID_USER_ACCOUNT_RESTRICTIONS = "4c164200-20c0-11d0-a768-00aa006e0529"

OBJECT_TYPES_GUID: Dict[str, str] = {}
OBJECT_TYPES_GUID.update({k.lower(): v for k, v in SCHEMA_OBJECTS.items()})
OBJECT_TYPES_GUID.update({k.lower(): v for k, v in EXTENDED_RIGHTS.items()})

WELL_KNOWN_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-10": "Principal Self",
    "S-1-5-18": "Local System",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
}


CSV_FIELDNAMES = [
    "target_dn",
    "target_sam",
    "target_class",
    "ace_index",
    "ace_type",
    "trustee_name",
    "trustee_sid",
    "rights",
    "mask",
    "object_type_name",
    "object_type_guid",
    "inherited_object_type_name",
    "inherited_object_type_guid",
    "inherited_ace",
    "inherit_only",
]


def domain_to_dn(domain: str) -> str:
    return ",".join("DC=%s" % p for p in domain.split(".") if p)


def get_base_dn(server: ldap3.Server, domain: str) -> str:
    try:
        values = server.info.other.get("defaultNamingContext")
        if values:
            return values[0]
    except Exception:
        pass

    derived = domain_to_dn(domain)
    if not derived:
        raise RuntimeError(
            "Could not determine the default naming context. "
            "Specify a DNS-style domain in the identity, for example CORP.LOCAL/user."
        )
    return derived


def raw_first(entry: ldap3.Entry, attribute: str) -> Optional[bytes]:
    try:
        values = entry[attribute].raw_values
        if values:
            return values[0]
    except (KeyError, IndexError, TypeError):
        pass
    return None


def text_first(entry: ldap3.Entry, attribute: str, default: str = "") -> str:
    try:
        value = entry[attribute].value
        if isinstance(value, list):
            return str(value[0]) if value else default
        return str(value) if value is not None else default
    except (KeyError, IndexError, TypeError):
        return default


def find_principal(
    connection: ldap3.Connection,
    base_dn: str,
    principal: str,
) -> Tuple[str, str, str, Optional[int], List[str]]:
    escaped = escape_filter_chars(principal)

    if principal.upper().startswith("S-1-"):
        search_filter = "(objectSid=%s)" % escaped
    elif "=" in principal and "," in principal:
        search_filter = "(distinguishedName=%s)" % escaped
    else:
        search_filter = "(sAMAccountName=%s)" % escaped

    ok = connection.search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=ldap3.SUBTREE,
        attributes=["objectSid", "sAMAccountName", "distinguishedName", "primaryGroupID", "sIDHistory"],
        size_limit=2,
    )
    if not ok or not connection.entries:
        raise RuntimeError("Principal not found in LDAP: %s" % principal)

    if len(connection.entries) > 1:
        raise RuntimeError("Principal lookup returned multiple entries: %s" % principal)

    entry = connection.entries[0]
    raw_sid = raw_first(entry, "objectSid")
    if raw_sid is None:
        raise RuntimeError("Principal has no objectSid: %s" % entry.entry_dn)

    primary_group_id = None
    try:
        value = entry["primaryGroupID"].value
        if value is not None:
            primary_group_id = int(value)
    except (KeyError, TypeError, ValueError):
        pass

    sid_history: List[str] = []
    try:
        for raw in entry["sIDHistory"].raw_values or []:
            sid_history.append(format_sid(raw))
    except (KeyError, TypeError):
        pass

    return (
        entry.entry_dn,
        format_sid(raw_sid),
        text_first(entry, "sAMAccountName", principal),
        primary_group_id,
        sid_history,
    )


def resolve_transitive_groups(
    connection: ldap3.Connection,
    base_dn: str,
    principal_dn: str,
) -> Dict[str, str]:
    """
    Return {group_sid: group_name} for every transitive group containing principal_dn.
    """
    escaped_dn = escape_filter_chars(principal_dn)
    search_filter = "(&(objectClass=group)(member:%s:=%s))" % (
        MATCHING_RULE_IN_CHAIN,
        escaped_dn,
    )

    groups: Dict[str, str] = {}
    entries = connection.extend.standard.paged_search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=ldap3.SUBTREE,
        attributes=["objectSid", "sAMAccountName", "distinguishedName"],
        paged_size=500,
        generator=True,
    )

    for item in entries:
        if item.get("type") != "searchResEntry":
            continue
        attrs = item.get("raw_attributes", {})
        sid_values = attrs.get("objectSid") or []
        if not sid_values:
            continue

        sid = format_sid(sid_values[0])
        display_attrs = item.get("attributes", {})
        name = (
            display_attrs.get("sAMAccountName")
            or display_attrs.get("distinguishedName")
            or item.get("dn")
            or sid
        )
        if isinstance(name, list):
            name = name[0] if name else sid
        groups[sid] = str(name)

    return groups


def classify_rights(mask: int, obj_guid: str, raw_rights: bool) -> List[str]:
    """Return a compact set of BloodHound-style ACL edge names."""
    edges: List[str] = []

    if mask & RIGHTS["GenericAll"]:
        return ["GenericAll"]
    if mask & RIGHTS["GenericWrite"]:
        edges.append("GenericWrite")
    if mask & RIGHTS["WriteDACL"]:
        edges.append("WriteDacl")
    if mask & RIGHTS["WriteOwner"]:
        edges.append("WriteOwner")

    if obj_guid:
        if mask & RIGHTS["ControlAccess"]:
            if obj_guid == GUID_RESET_PASSWORD:
                edges.append("ForceChangePassword")
            elif obj_guid == GUID_GET_CHANGES:
                edges.append("GetChanges")
            elif obj_guid == GUID_GET_CHANGES_ALL:
                edges.append("GetChangesAll")
            elif obj_guid == GUID_GET_CHANGES_FILTERED:
                edges.append("GetChangesInFilteredSet")
            elif raw_rights:
                edges.append("ExtendedRight:%s" % obj_guid)

        if mask & RIGHTS["WriteProperty"]:
            if obj_guid == GUID_MEMBER:
                edges.append("AddMember")
            elif obj_guid == GUID_SERVICE_PRINCIPAL_NAME:
                edges.append("WriteSPN")
            elif obj_guid == GUID_KEY_CREDENTIAL_LINK:
                edges.append("AddKeyCredentialLink")
            elif obj_guid == GUID_ALLOWED_TO_ACT:
                edges.append("AddAllowedToAct")
            elif obj_guid == GUID_USER_ACCOUNT_RESTRICTIONS:
                edges.append("WriteAccountRestrictions")
            elif raw_rights:
                edges.append("WriteProperty:%s" % obj_guid)

        if mask & RIGHTS["Self"]:
            if obj_guid == GUID_MEMBER:
                edges.append("AddSelf")
            elif raw_rights:
                edges.append("Self:%s" % obj_guid)
    else:
        # An unscoped ADS_RIGHT_DS_WRITE_PROP ACE applies to all properties.
        # BloodHound represents this as GenericWrite even when the directory
        # stores the mapped specific bit (0x20), rather than the literal
        # GENERIC_WRITE bit (0x40000000).
        if mask & RIGHTS["WriteProperty"]:
            edges.append("GenericWrite")

        # CONTROL_ACCESS without an ObjectType GUID means all extended rights.
        if mask & RIGHTS["ControlAccess"]:
            edges.append("AllExtendedRights")

        if raw_rights and (mask & RIGHTS["Self"]):
            edges.append("Self")

    # Preserve order while removing duplicate classifications.
    return list(dict.fromkeys(edges))

def object_guid(ace) -> Tuple[str, str]:
    try:
        data = ace["Ace"]
        if data["ObjectTypeLen"] == 0:
            return "", ""
        guid = bin_to_string(data["ObjectType"]).lower()
        return guid, OBJECT_TYPES_GUID.get(guid, "UNKNOWN")
    except Exception:
        return "", ""


def inherited_object_guid(ace) -> Tuple[str, str]:
    try:
        data = ace["Ace"]
        if data["InheritedObjectTypeLen"] == 0:
            return "", ""
        guid = bin_to_string(data["InheritedObjectType"]).lower()
        return guid, OBJECT_TYPES_GUID.get(guid, "UNKNOWN")
    except Exception:
        return "", ""


def ace_is_allowed(ace) -> bool:
    return ace["TypeName"] in ("ACCESS_ALLOWED_ACE", "ACCESS_ALLOWED_OBJECT_ACE")


def ace_is_denied(ace) -> bool:
    return ace["TypeName"] in ("ACCESS_DENIED_ACE", "ACCESS_DENIED_OBJECT_ACE")


def ace_is_inherit_only(ace) -> bool:
    try:
        return ace.hasFlag(ldaptypes.ACE.INHERIT_ONLY_ACE)
    except Exception:
        return False


def ace_is_inherited(ace) -> bool:
    try:
        return ace.hasFlag(ldaptypes.ACE.INHERITED_ACE)
    except Exception:
        return False


def parse_matching_aces(
    raw_sd: bytes,
    token_sids: Set[str],
    sid_names: Dict[str, str],
    include_denies: bool,
    include_inherit_only: bool,
    raw_rights: bool,
    context: str = "",
) -> Iterable[dict]:
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
    dacl = sd["Dacl"]
    if dacl is None:
        logging.warning(
            "Null DACL on %s -- no DACL present, which grants full control to "
            "everyone; not represented in results",
            context or "<unknown object>",
        )
        return

    aces = getattr(dacl, "aces", None)
    if aces is None:
        aces = dacl["Data"]

    for ace_index, ace in enumerate(aces):
        if not (ace_is_allowed(ace) or (include_denies and ace_is_denied(ace))):
            continue
        if ace_is_inherit_only(ace) and not include_inherit_only:
            continue

        try:
            trustee_sid = ace["Ace"]["Sid"].formatCanonical()
            mask = int(ace["Ace"]["Mask"]["Mask"])
        except Exception:
            continue

        if trustee_sid not in token_sids:
            continue

        obj_guid, obj_name = object_guid(ace)
        inherited_guid, inherited_name = inherited_object_guid(ace)

        rights = classify_rights(mask, obj_guid, raw_rights)
        if not rights:
            continue

        yield {
            "ace_index": ace_index,
            "ace_type": "DENY" if ace_is_denied(ace) else "ALLOW",
            "trustee_sid": trustee_sid,
            "trustee_name": sid_names.get(trustee_sid, trustee_sid),
            "mask": "0x%08x" % mask,
            "rights": ",".join(rights),
            "object_type_guid": obj_guid,
            "object_type_name": obj_name,
            "inherited_object_type_guid": inherited_guid,
            "inherited_object_type_name": inherited_name,
            "inherited_ace": str(ace_is_inherited(ace)),
            "inherit_only": str(ace_is_inherit_only(ace)),
        }


def security_descriptor_owner(raw_sd: bytes) -> str:
    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
        owner = sd["OwnerSid"]
        return owner.formatCanonical() if owner is not None else ""
    except Exception:
        return ""



def resolve_sid_name(
    connection: ldap3.Connection,
    base_dn: str,
    sid: str,
    cache: Dict[str, str],
) -> str:
    if sid in cache:
        return cache[sid]
    if sid in WELL_KNOWN_SIDS:
        cache[sid] = WELL_KNOWN_SIDS[sid]
        return cache[sid]

    connection.search(
        search_base=base_dn,
        search_filter="(objectSid=%s)" % escape_filter_chars(sid),
        search_scope=ldap3.SUBTREE,
        attributes=["sAMAccountName", "distinguishedName"],
        size_limit=1,
    )
    name = sid
    if connection.entries:
        entry = connection.entries[0]
        name = text_first(entry, "sAMAccountName", entry.entry_dn)
    cache[sid] = name
    return name


def parse_all_relevant_aces(
    raw_sd: bytes,
    include_denies: bool,
    include_inherit_only: bool,
    raw_rights: bool,
    context: str = "",
) -> Iterable[dict]:
    """Parse attack-relevant ACEs without filtering by a particular trustee."""
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
    dacl = sd["Dacl"]
    if dacl is None:
        logging.warning(
            "Null DACL on %s -- no DACL present, which grants full control to "
            "everyone; not represented in results",
            context or "<unknown object>",
        )
        return

    aces = getattr(dacl, "aces", None)
    if aces is None:
        aces = dacl["Data"]

    for ace_index, ace in enumerate(aces):
        if not (ace_is_allowed(ace) or (include_denies and ace_is_denied(ace))):
            continue
        if ace_is_inherit_only(ace) and not include_inherit_only:
            continue

        try:
            trustee_sid = ace["Ace"]["Sid"].formatCanonical()
            mask = int(ace["Ace"]["Mask"]["Mask"])
        except Exception:
            continue

        obj_guid, obj_name = object_guid(ace)
        inherited_guid, inherited_name = inherited_object_guid(ace)
        rights = classify_rights(mask, obj_guid, raw_rights)
        if not rights:
            continue

        yield {
            "ace_index": ace_index,
            "ace_type": "DENY" if ace_is_denied(ace) else "ALLOW",
            "trustee_sid": trustee_sid,
            "mask": "0x%08x" % mask,
            "rights": ",".join(rights),
            "object_type_guid": obj_guid,
            "object_type_name": obj_name,
            "inherited_object_type_guid": inherited_guid,
            "inherited_object_type_name": inherited_name,
            "inherited_ace": str(ace_is_inherited(ace)),
            "inherit_only": str(ace_is_inherit_only(ace)),
        }


def get_single_object_sd(
    connection: ldap3.Connection,
    base_dn: str,
    target: str,
) -> dict:
    escaped = escape_filter_chars(target)
    if target.upper().startswith("S-1-"):
        search_filter = "(objectSid=%s)" % escaped
    elif "=" in target and "," in target:
        search_filter = "(distinguishedName=%s)" % escaped
    else:
        search_filter = "(sAMAccountName=%s)" % escaped

    controls = security_descriptor_control(sdflags=0x05)
    ok = connection.search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=ldap3.SUBTREE,
        attributes=[
            "distinguishedName",
            "sAMAccountName",
            "objectClass",
            "objectSid",
            "nTSecurityDescriptor",
        ],
        size_limit=2,
        controls=controls,
    )
    if not ok or not connection.entries:
        raise RuntimeError("Target object not found in LDAP: %s" % target)
    if len(connection.entries) > 1:
        raise RuntimeError("Target lookup returned multiple entries: %s" % target)

    entry = connection.entries[0]
    raw_sd = raw_first(entry, "nTSecurityDescriptor")
    if raw_sd is None:
        raise RuntimeError("Target has no readable nTSecurityDescriptor: %s" % entry.entry_dn)

    raw_sid = raw_first(entry, "objectSid")
    return {
        "dn": entry.entry_dn,
        "sam": text_first(entry, "sAMAccountName", target),
        "class": object_class_string(entry["objectClass"].value),
        "sid": format_sid(raw_sid) if raw_sid is not None else "",
        "raw_sd": raw_sd,
    }


def run_target_mode(
    connection: ldap3.Connection,
    base_dn: str,
    args,
) -> int:
    target = get_single_object_sd(connection, base_dn, args.target)
    sid_cache: Dict[str, str] = dict(WELL_KNOWN_SIDS)

    print("Target: %s" % target["sam"])
    print("DN: %s" % target["dn"])
    if target["sid"]:
        print("SID: %s" % target["sid"])
    print("Class: %s" % target["class"])
    print()

    csv_file = None
    writer = None
    if args.csv_path:
        csv_file = open(args.csv_path, "w", newline="", encoding="utf-8")
        writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()

    # Target-object columns shared by every row emitted in this mode.
    target_columns = {
        "target_dn": str(target["dn"]),
        "target_sam": str(target["sam"]),
        "target_class": str(target["class"]),
    }

    findings = 0
    try:
        owner_sid = security_descriptor_owner(target["raw_sd"])
        if owner_sid:
            owner_name = resolve_sid_name(connection, base_dn, owner_sid, sid_cache)
            print("[OWNER] Owns                     %s (%s)" % (owner_name, owner_sid))
            findings += 1
            if writer:
                writer.writerow({
                    **target_columns,
                    "ace_index": -1,
                    "ace_type": "OWNER",
                    "trustee_name": owner_name,
                    "trustee_sid": owner_sid,
                    "rights": "Owns",
                    "mask": "",
                    "object_type_name": "",
                    "object_type_guid": "",
                    "inherited_object_type_name": "",
                    "inherited_object_type_guid": "",
                    "inherited_ace": "False",
                    "inherit_only": "False",
                })

        for finding in parse_all_relevant_aces(
            target["raw_sd"],
            args.include_denies,
            args.include_inherit_only,
            args.raw_rights,
            context=str(target["dn"]),
        ):
            trustee_name = resolve_sid_name(
                connection, base_dn, finding["trustee_sid"], sid_cache
            )
            object_suffix = ""
            if finding["object_type_guid"]:
                object_suffix = " [ObjectType: %s (%s)]" % (
                    finding["object_type_name"],
                    finding["object_type_guid"],
                )
            print(
                "[{ace_type}] {rights:<24} {name} ({sid}){suffix}".format(
                    ace_type=finding["ace_type"],
                    rights=finding["rights"],
                    name=trustee_name,
                    sid=finding["trustee_sid"],
                    suffix=object_suffix,
                )
            )
            findings += 1
            if writer:
                writer.writerow({
                    **target_columns,
                    "trustee_name": trustee_name,
                    **finding,
                })
    finally:
        if csv_file:
            csv_file.close()

    logging.info("Finished: %d inbound ownership/ACE finding(s)", findings)
    if args.csv_path:
        logging.info("CSV written to %s", args.csv_path)
    return 0


def enumerate_objects(
    connection: ldap3.Connection,
    base_dn: str,
    ldap_filter: str,
    page_size: int,
):
    controls = security_descriptor_control(sdflags=0x05)

    return connection.extend.standard.paged_search(
        search_base=base_dn,
        search_filter=ldap_filter,
        search_scope=ldap3.SUBTREE,
        attributes=[
            "distinguishedName",
            "sAMAccountName",
            "objectClass",
            "objectSid",
            "nTSecurityDescriptor",
        ],
        paged_size=page_size,
        generator=True,
        controls=controls,
    )


def object_class_string(value) -> str:
    if isinstance(value, (list, tuple)):
        return str(value[-1]) if value else ""
    return str(value or "")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Enumerate outbound rights for a principal or inbound attack-relevant ACLs on one target object."
    )
    parser.add_argument(
        "identity",
        help="Authentication identity: domain.local/username[:password]",
    )
    direction = parser.add_mutually_exclusive_group(required=True)
    direction.add_argument(
        "-principal",
        help="Principal whose outbound rights over directory objects are checked.",
    )
    direction.add_argument(
        "-target",
        help="Target object whose inbound attack-relevant ACL entries are listed.",
    )
    parser.add_argument(
        "-groups",
        action="store_true",
        help="Also print the principal's transitive group memberships before ACL results.",
    )
    parser.add_argument(
        "-groups-only",
        action="store_true",
        help="Print the principal's transitive and primary groups, then exit without scanning ACLs.",
    )
    parser.add_argument(
        "-ldap-filter",
        default="(objectClass=*)",
        help="LDAP filter for target objects. Default: (objectClass=*)",
    )
    parser.add_argument(
        "-base-dn",
        help="LDAP search base. Default: domain defaultNamingContext.",
    )
    parser.add_argument(
        "-page-size",
        type=int,
        default=500,
        help="LDAP page size. Default: 500.",
    )
    parser.add_argument(
        "-csv",
        dest="csv_path",
        help="Write findings to a CSV file instead of only printing them.",
    )
    parser.add_argument(
        "-no-groups",
        action="store_true",
        help="Do not include transitive group memberships.",
    )
    parser.add_argument(
        "-include-well-known",
        action="store_true",
        help="Include Everyone and Authenticated Users ACEs. Disabled by default to reduce default-ACL noise.",
    )
    parser.add_argument(
        "-include-denies",
        action="store_true",
        help="Also display matching deny ACEs. Denies are not evaluated against allows.",
    )
    parser.add_argument(
        "-include-inherit-only",
        action="store_true",
        help="Include INHERIT_ONLY ACEs that do not apply to the object carrying the DACL.",
    )
    parser.add_argument(
        "-raw-rights",
        action="store_true",
        help="Also show unrecognized scoped write/extended rights. Default output stays BloodHound-like and quiet.",
    )
    parser.add_argument(
        "-use-ldaps",
        action="store_true",
        help="Use LDAPS on port 636.",
    )
    parser.add_argument("-hashes", metavar="LMHASH:NTHASH")
    parser.add_argument("-no-pass", action="store_true")
    parser.add_argument("-k", action="store_true", help="Use Kerberos / KRB5CCNAME.")
    parser.add_argument("-aesKey", metavar="HEXKEY")
    parser.add_argument("-dc-ip", help="Domain controller/KDC IP address.")
    parser.add_argument("-dc-host", help="Domain controller FQDN; recommended with Kerberos.")
    parser.add_argument("-debug", action="store_true")
    parser.add_argument("-ts", action="store_true")
    return parser


def main() -> int:
    print(version.BANNER)
    args = build_parser().parse_args()
    logger.init(args.ts, args.debug)

    # Unpack the first six values and absorb anything a future impacket release
    # appends. Old impacket (<6-tuple) is intentionally unsupported and will
    # raise here.
    (
        domain,
        username,
        password,
        lmhash,
        nthash,
        use_kerberos,
        *_extra_identity_fields,
    ) = parse_identity(
        args.identity,
        args.hashes,
        args.no_pass,
        args.aesKey,
        args.k,
    )

    if use_kerberos and not args.dc_host:
        logging.warning(
            "Kerberos works most reliably with -dc-host set to the DC FQDN "
            "matching the LDAP service ticket."
        )

    ldap_server, ldap_session = init_ldap_session(
        domain,
        username,
        password,
        lmhash,
        nthash,
        use_kerberos,
        args.dc_ip,
        args.dc_host,
        args.aesKey,
        args.use_ldaps,
    )

    base_dn = args.base_dn or get_base_dn(ldap_server, domain)

    if args.target:
        if args.groups or args.groups_only:
            raise RuntimeError("-groups and -groups-only require -principal")
        return run_target_mode(ldap_session, base_dn, args)

    principal_dn, principal_sid, principal_name, primary_group_id, sid_history = find_principal(
        ldap_session,
        base_dn,
        args.principal,
    )

    groups: Dict[str, str] = {}
    primary_sid = None

    if not args.no_groups or args.groups or args.groups_only:
        groups = resolve_transitive_groups(ldap_session, base_dn, principal_dn)

        # The primary group is not represented by member/memberOf and therefore
        # is not returned by LDAP_MATCHING_RULE_IN_CHAIN. Add it explicitly.
        if primary_group_id is not None and "-" in principal_sid:
            primary_sid = principal_sid.rsplit("-", 1)[0] + "-" + str(primary_group_id)
            if primary_sid not in groups:
                ldap_session.search(
                    base_dn,
                    "(objectSid=%s)" % escape_filter_chars(primary_sid),
                    attributes=["sAMAccountName", "distinguishedName"],
                    size_limit=1,
                )
                primary_name = primary_sid
                if ldap_session.entries:
                    primary_name = text_first(ldap_session.entries[0], "sAMAccountName", primary_sid)
                groups[primary_sid] = primary_name

    if args.groups or args.groups_only:
        print("Target: %s" % principal_name)
        print("DN: %s" % principal_dn)
        print("SID: %s" % principal_sid)
        print("Groups (%d):" % len(groups))
        for sid, name in sorted(groups.items(), key=lambda item: item[1].lower()):
            suffix = " [primary]" if sid == primary_sid else ""
            print("  %-40s %s%s" % (name, sid, suffix))
        print()

    if args.groups_only:
        return 0

    sid_names: Dict[str, str] = {principal_sid: principal_name}
    token_sids: Set[str] = {principal_sid}

    for historical_sid in sid_history:
        token_sids.add(historical_sid)
        sid_names[historical_sid] = "%s (SIDHistory)" % principal_name

    if not args.no_groups:
        sid_names.update(groups)
        token_sids.update(groups.keys())
        logging.info("Resolved %d group SID(s), including the primary group", len(groups))

    if args.include_well_known:
        token_sids.update(("S-1-1-0", "S-1-5-11"))
        sid_names.update(WELL_KNOWN_SIDS)

    logging.info("Principal: %s", principal_name)
    logging.info("Principal DN: %s", principal_dn)
    logging.info("Principal SID: %s", principal_sid)
    logging.info("Search base: %s", base_dn)
    logging.info("Target filter: %s", args.ldap_filter)

    csv_file = None
    writer = None
    if args.csv_path:
        csv_file = open(args.csv_path, "w", newline="", encoding="utf-8")
        writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()

    scanned = 0
    findings = 0
    parse_errors = 0

    try:
        for item in enumerate_objects(
            ldap_session,
            base_dn,
            args.ldap_filter,
            args.page_size,
        ):
            if item.get("type") != "searchResEntry":
                continue

            scanned += 1
            raw_attrs = item.get("raw_attributes", {})
            sd_values = raw_attrs.get("nTSecurityDescriptor") or []
            if not sd_values:
                continue

            attrs = item.get("attributes", {})
            target_dn = item.get("dn") or attrs.get("distinguishedName") or ""
            target_sam = attrs.get("sAMAccountName") or ""
            target_class = object_class_string(attrs.get("objectClass"))

            if isinstance(target_sam, list):
                target_sam = target_sam[0] if target_sam else ""

            try:
                owner_sid = security_descriptor_owner(sd_values[0])
                if owner_sid in token_sids:
                    findings += 1
                    owner_row = {
                        "target_dn": str(target_dn),
                        "target_sam": str(target_sam),
                        "target_class": target_class,
                        "ace_index": -1,
                        "ace_type": "OWNER",
                        "trustee_name": sid_names.get(owner_sid, owner_sid),
                        "trustee_sid": owner_sid,
                        "rights": "Owns",
                        "mask": "",
                        "object_type_name": "",
                        "object_type_guid": "",
                        "inherited_object_type_name": "",
                        "inherited_object_type_guid": "",
                        "inherited_ace": "False",
                        "inherit_only": "False",
                    }
                    print("[OWNER] Owns                     {trustee_name} ({trustee_sid}) -> {target_dn}".format(**owner_row))
                    if writer:
                        writer.writerow(owner_row)

                matches = parse_matching_aces(
                    sd_values[0],
                    token_sids,
                    sid_names,
                    args.include_denies,
                    args.include_inherit_only,
                    args.raw_rights,
                    context=str(target_dn),
                )
                for finding in matches:
                    findings += 1
                    row = {
                        "target_dn": str(target_dn),
                        "target_sam": str(target_sam),
                        "target_class": target_class,
                        **finding,
                    }

                    print(
                        "[{ace_type}] {rights:<24} {trustee_name} ({trustee_sid}) -> "
                        "{target_dn}{object_suffix}".format(
                            object_suffix=(
                                " [ObjectType: %s (%s)]"
                                % (
                                    row["object_type_name"],
                                    row["object_type_guid"],
                                )
                                if row["object_type_guid"]
                                else ""
                            ),
                            **row,
                        )
                    )

                    if writer:
                        writer.writerow(row)

            except Exception as exc:
                parse_errors += 1
                logging.debug("Could not parse DACL for %s: %s", target_dn, exc)

    finally:
        if csv_file:
            csv_file.close()

    logging.info(
        "Finished: %d objects scanned, %d matching ACE(s), %d DACL parse error(s)",
        scanned,
        findings,
        parse_errors,
    )
    if args.csv_path:
        logging.info("CSV written to %s", args.csv_path)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logging.error("Interrupted")
        sys.exit(130)
    except Exception as exc:
        if "-debug" in sys.argv:
            traceback.print_exc()
        logging.error(str(exc))
        sys.exit(1)
