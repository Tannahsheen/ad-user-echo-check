## AD User Export + SMB Username=Username Check

This tool:
- Enumerates AD users via LDAP (with credentials) or SMB null session.
- Exports sAMAccountName values to `user-export.txt`.
- Attempts exactly one SMB login per user with password equal to their username (e.g., `alice:alice`). This is NOT brute forcing.

Only use with explicit authorization.

### Install

python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt

### Usage

- LDAP (recommended):
- 
python ad_username_check.py --dc dc01.example.com --domain example.com --username adminuser --password 'S3cret!' --ldaps- SMB null session (no creds; only if DC allows anonymous SAMR):

python ad_username_check.py --dc dc01.example.com --domain example.com- Custom base DN and small delay between SMB attempts:

python ad_username_check.py --dc dc01.example.com --domain example.com --base-dn "DC=example,DC=com" --smb-delay 0.05Output file: `user-export.txt`

### Notes

- Null sessions *should* be blocked, but arent always, so its worth checking. You should typically be supplying creds. 
- “Echo check” is some bullshit term i made up. This is priobably more accurately called a “username=password” or “username:username” check.
