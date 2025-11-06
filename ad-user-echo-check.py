#!/usr/bin/env python3
import argparse
import sys
import time
import ssl
from typing import List, Optional

from ldap3 import Server, Connection, ALL, NTLM, Tls, SUBTREE
from ldap3.core.exceptions import LDAPException

from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5 import transport, samr


def domain_to_base_dn(domain: str) -> str:
    return ",".join([f"DC={part}" for part in domain.split(".")])


def fetch_enabled_users_ldap(dc: str, domain: str, username: str, password: str, use_ldaps: bool, search_base: Optional[str] = None, page_size: int = 1000) -> List[str]:
    base_dn = search_base or domain_to_base_dn(domain)
    tls = None
    if use_ldaps:
        tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT)

    server = Server(dc, use_ssl=use_ldaps, get_info=ALL, tls=tls)
    try:
        conn = Connection(
            server,
            user=f"{domain}\\{username}",
            password=password,
            authentication=NTLM,
            auto_bind=True,
            receive_timeout=20,
        )
    except LDAPException as e:
        raise RuntimeError(f"LDAP bind failed: {e}") from e

    ldap_filter = "(&(objectClass=user)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(sAMAccountName=*))"
    attributes = ["sAMAccountName"]

    users = []
    try:
        cookie = None
        while True:
            conn.search(
                search_base=base_dn,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=attributes,
                paged_size=page_size,
                paged_cookie=cookie,
            )
            for entry in conn.entries:
                sam = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else None
                if sam:
                    users.append(sam)
            cookie = conn.result.get("controls", {}).get("1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")
            if not cookie:
                break
    finally:
        conn.unbind()

    return sorted(set(users), key=str.lower)


def enumerate_users_via_null_session(dc: str, domain: str) -> List[str]:
    """
    SMB null session + SAMR user enumeration.
    Works only if DC allows anonymous SAMR (often disabled).
    """
    smb = SMBConnection(remoteName=dc, remoteHost=dc, sess_port=445, timeout=10)
    try:
        smb.login('', '', domain)
    except Exception as e:
        raise RuntimeError(f"Null session login failed: {e}")

    rpctrans = transport.SMBTransport(dc, 445, r'\samr', smb_connection=smb)
    dce = None
    try:
        dce = rpctrans.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        server_handle = samr.hSamrConnect(dce)['ServerHandle']
        domains = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)['Buffer']['Buffer']

        target_domain = None
        short = domain.split('.')[0].lower()
        for dom in domains:
            name = str(dom['Name']).lower()
            if name == short:
                target_domain = dom['Name']
                break
        if not target_domain and domains:
            target_domain = domains[0]['Name']
        if not target_domain:
            raise RuntimeError("Could not find a domain via SAMR enumeration")

        resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, target_domain)
        domain_sid = resp['DomainId']
        domain_handle = samr.hSamrOpenDomain(
            dce,
            server_handle=server_handle,
            desired_access=samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS | samr.DOMAIN_READ,
            domain_id=domain_sid
        )['DomainHandle']

        users = []
        enumeration_context = 0
        while True:
            try:
                enum_resp = samr.hSamrEnumerateUsersInDomain(
                    dce,
                    domain_handle,
                    enumeration_context,
                    samr.USER_NORMAL_ACCOUNT,
                    1000
                )
            except samr.DCERPCSessionError as e:
                if 'STATUS_MORE_ENTRIES' in str(e):
                    enum_resp = e.get_packet()
                else:
                    raise

            if 'Buffer' in enum_resp and enum_resp['Buffer'] is not None:
                for user in enum_resp['Buffer']['Buffer']:
                    name = str(user['Name']).strip()
                    if name:
                        users.append(name)

            enumeration_context = enum_resp['EnumerationContext']
            if enum_resp['ErrorCode'] == 0:
                break

        return sorted(set(users), key=str.lower)
    finally:
        try:
            if dce:
                dce.disconnect()
        except Exception:
            pass
        try:
            smb.logoff()
        except Exception:
            pass


def write_users(path: str, users: List[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for u in users:
            f.write(f"{u}\n")


def try_smb_username_equals(dc: str, domain: str, user: str, delay: float = 0.0) -> bool:
    conn = SMBConnection(remoteName=dc, remoteHost=dc, sess_port=445, timeout=10)
    try:
        conn.login(user, user, domain)
        return True
    except SessionError:
        return False
    except Exception:
        return False
    finally:
        try:
            conn.logoff()
        except Exception:
            pass
        if delay > 0:
            time.sleep(delay)


def main():
    parser = argparse.ArgumentParser(
        description="Export AD users (LDAP or SMB null session) and test one SMB login per user with username=username."
    )
    parser.add_argument("--dc", required=True, help="Domain Controller hostname or IP (e.g., dc01.example.com)")
    parser.add_argument("--domain", required=True, help="AD domain (e.g., example.com)")
    parser.add_argument("--username", help="AD username for LDAP bind (optional; if absent, try SMB null session enumeration)")
    parser.add_argument("--password", help="AD password for LDAP bind")
    parser.add_argument("--ldaps", action="store_true", help="Use LDAPS (TCP 636, no cert validation)")
    parser.add_argument("--base-dn", help="Optional LDAP base DN (e.g., DC=example,DC=com)")
    parser.add_argument("--output", default="user-export.txt", help="Output file for user list")
    parser.add_argument("--smb-delay", type=float, default=0.0, help="Delay in seconds between SMB attempts")
    parser.add_argument("--max-users", type=int, default=0, help="Limit number of users processed (0 = no limit)")
    args = parser.parse_args()

    # Get users
    if args.username and args.password:
        try:
            users = fetch_enabled_users_ldap(
                dc=args.dc,
                domain=args.domain,
                username=args.username,
                password=args.password,
                use_ldaps=args.ldaps,
                search_base=args.base_dn,
            )
        except Exception as e:
            print(f"[!] LDAP enumeration failed: {e}")
            sys.exit(1)
    else:
        try:
            users = enumerate_users_via_null_session(args.dc, args.domain)
            if not users:
                print("[!] Null session succeeded but returned no users.")
        except Exception as e:
            print(f"[!] Null session enumeration failed: {e}")
            print("    Tip: Provide --username/--password for LDAP-based enumeration instead.")
            sys.exit(1)

    if args.max_users and args.max_users > 0:
        users = users[: args.max_users]

    write_users(args.output, users)
    print(f"[+] Exported {len(users)} users to {args.output}")

    # SMB username=username check (single attempt per user)
    print("[+] Testing SMB logins (username=username) against DC...")
    found = []
    for u in users:
        if try_smb_username_equals(args.dc, args.domain, u, delay=args.smb_delay):
            found.append(u)
            print(f"  [+] WEAK: {u}:{u}")

    print("\n=== SMB Username=Username Check Summary ===")
    print(f"DC: {args.dc}")
    print(f"Total users tested: {len(users)}")
    print(f"Weak accounts found: {len(found)}")
    if found:
        print("List of weak accounts:")
        for u in found:
            print(f"  {u}:{u}")


if __name__ == "__main__":
    main()
