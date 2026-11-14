
#!/usr/bin/env python3

import os
import re
import pwd
import grp
import platform
import socket
import subprocess
import datetime
import shutil
import stat
import glob
import psutil
import json

from pathlib import Path
from collections import defaultdict
# ==========================================================
#                    HELPER FUNCTIONS
# ==========================================================

def run_command(command):
    """Execute a system command safely."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15
        )
        return result.stdout.strip() or "No information available"

    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "Command unavailable or timed out"

    except Exception as error:
        return f"Error: {error}"


def read_file(path):
    """Read system configuration files."""
    try:
        with open(path, "r") as file:
            return file.read().strip()
    except (OSError, PermissionError):
        return "Not available"


def section(title):
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def display_table(headers, rows):
    """Display information in a formatted table."""

    if not rows:
        print("No records available.")
        return

    widths = []

    for i, header in enumerate(headers):
        widths.append(
            max(
                len(str(header)),
                max(len(str(row[i])) for row in rows)
            )
        )

    header_line = " | ".join(
        str(headers[i]).ljust(widths[i])
        for i in range(len(headers))
    )

    print(header_line)
    print("-" * len(header_line))

    for row in rows:
        print(" | ".join(
            str(row[i]).ljust(widths[i])
            for i in range(len(headers))
        ))


# ==========================================================
#                 1. SYSTEM INFORMATION
# ==========================================================

def system_information():

    section("1. OPERATING SYSTEM INFORMATION")

    os_release = read_file("/etc/os-release")

    distribution = "Unknown"

    if os_release != "Not available":
        match = re.search(r'^PRETTY_NAME="?([^"\n]+)', os_release, re.M)
        if match:
            distribution = match.group(1)

    print("Operating System :", platform.system())
    print("Distribution     :", distribution)
    print("OS Version       :", platform.version())
    print("Kernel Version   :", platform.release())
    print("Architecture     :", platform.machine())
    print("Build            :", platform.uname().version)

    section("2. HOST INFORMATION")

    print("Hostname         :", socket.gethostname())
    print("FQDN             :", socket.getfqdn())
    print("Computer Name    :", platform.node())

    section("3. SYSTEM UPTIME")

    uptime = read_file("/proc/uptime")

    if uptime != "Not available":
        seconds = float(uptime.split()[0])
        print("System Uptime    :", datetime.timedelta(seconds=int(seconds)))

    print("Boot Time        :", run_command(["uptime", "-s"]))

    section("4. CPU INFORMATION")

    cpu_info = read_file("/proc/cpuinfo")

    model = re.search(r"model name\s*:\s*(.+)", cpu_info)

    print("CPU Model        :", model.group(1) if model else "Unknown")
    print("CPU Cores        :", os.cpu_count())

    section("5. MEMORY INFORMATION")

    meminfo = read_file("/proc/meminfo")

    for key in ["MemTotal", "MemFree", "MemAvailable", "SwapTotal"]:
        match = re.search(rf"^{key}:\s*(.+)", meminfo, re.M)
        print(f"{key:18}: {match.group(1) if match else 'Unknown'}")

    section("6. DISK INFORMATION")

    print(run_command([
        "lsblk",
        "-o",
        "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT"
    ]))

    section("7. HARDWARE INFORMATION")

    hardware = {
        "Manufacturer": "/sys/class/dmi/id/sys_vendor",
        "Product Model": "/sys/class/dmi/id/product_name",
        "Product Version": "/sys/class/dmi/id/product_version",
        "BIOS Version": "/sys/class/dmi/id/bios_version"
    }

    for name, path in hardware.items():
        print(f"{name:18}: {read_file(path)}")

    section("8. VIRTUALIZATION INFORMATION")

    print("Virtualization    :", run_command(["systemd-detect-virt"]))

    section("9. INSTALLED PACKAGES")

    if shutil.which("dpkg-query"):
        print("Package Manager: DPKG")
        print(run_command([
            "dpkg-query",
            "-W",
            "-f=${binary:Package} ${Version}\n"
        ]))

    elif shutil.which("rpm"):
        print("Package Manager: RPM")
        print(run_command(["rpm", "-qa"]))

    else:
        print("Package manager unavailable.")

    section("10. DOMAIN INFORMATION")

    print("DNS Domain        :", run_command(["dnsdomainname"]))

    if shutil.which("realm"):
        print("\nDomain Membership:")
        print(run_command(["realm", "list"]))

    if shutil.which("testparm"):
        print("\nSamba Configuration:")
        print(run_command(["testparm", "-s"]))


# ==========================================================
#               2. USER AND ACCOUNT INFORMATION
# ==========================================================

def user_account_information():

    users = pwd.getpwall()

    # ------------------------------------------------------
    # 11. CURRENTLY LOGGED-IN USERS
    # ------------------------------------------------------

    section("11. CURRENTLY LOGGED-IN USERS")

    print(run_command(["who", "-H"]))

    print("\nSession Information:")
    print(run_command(["w"]))

    # ------------------------------------------------------
    # 12. LOCAL USER ACCOUNTS
    # ------------------------------------------------------

    section("12. LOCAL USER ACCOUNTS")

    rows = []

    for user in users:
        rows.append([
            user.pw_name,
            user.pw_uid,
            user.pw_gid,
            user.pw_dir,
            user.pw_shell
        ])

    display_table(
        ["Username", "UID", "GID", "Home Directory", "Login Shell"],
        rows
    )

    # ------------------------------------------------------
    # 13. ADMINISTRATOR ACCOUNTS
    # ------------------------------------------------------

    section("13. ADMINISTRATOR ACCOUNTS")

    admin_users = set()

    for group_name in ["sudo", "wheel"]:
        try:
            group = grp.getgrnam(group_name)
            admin_users.update(group.gr_mem)
        except KeyError:
            pass

    for user in users:
        if user.pw_uid == 0:
            admin_users.add(user.pw_name)

    for username in sorted(admin_users):
        print("[ADMIN]", username)

    if not admin_users:
        print("No administrator accounts identified.")

    # ------------------------------------------------------
    # 14. USER GROUP MEMBERSHIPS
    # ------------------------------------------------------

    section("14. USER GROUP MEMBERSHIPS")

    group_rows = []

    for group in grp.getgrall():

        members = set(group.gr_mem)

        for user in users:
            if group.gr_gid in os.getgrouplist(
                user.pw_name, user.pw_gid
            ):
                members.add(user.pw_name)

        group_rows.append([
            group.gr_name,
            group.gr_gid,
            ", ".join(sorted(members)) or "-"
        ])

    display_table(
        ["Group Name", "GID", "Members"],
        group_rows
    )

    # ------------------------------------------------------
    # 15. USER PRIVILEGES
    # ------------------------------------------------------

    section("15. USER PRIVILEGES AND PERMISSIONS")

    print("Current Process Identity:")
    print(run_command(["id"]))

    if shutil.which("sudo"):
        print("\nSudo Privileges:")

        print(run_command(["sudo", "-n", "-l"]))

    # ------------------------------------------------------
    # 16. HOME DIRECTORIES
    # ------------------------------------------------------

    section("16. USER PROFILES AND HOME DIRECTORIES")

    home_rows = []

    for user in users:

        home = user.pw_dir

        if home and os.path.isdir(home):

            try:
                permissions = oct(
                    os.stat(home).st_mode & 0o777
                )
            except OSError:
                permissions = "Unknown"

            home_rows.append([
                user.pw_name,
                home,
                permissions
            ])

    display_table(
        ["Username", "Home Directory", "Permissions"],
        home_rows
    )

    # ------------------------------------------------------
    # 17. SERVICE ACCOUNTS
    # ------------------------------------------------------

    section("17. SERVICE ACCOUNTS")

    service_rows = []

    for user in users:

        if 0 < user.pw_uid < 1000:

            service_rows.append([
                user.pw_name,
                user.pw_uid,
                user.pw_shell,
                user.pw_dir
            ])

    display_table(
        ["Account", "UID", "Shell", "Home Directory"],
        service_rows
    )

    # ------------------------------------------------------
    # 18. LOCKED AND NON-LOGIN ACCOUNTS
    # ------------------------------------------------------

    section("18. LOCKED AND NON-LOGIN ACCOUNTS")

    passwd_status = {}

    if shutil.which("passwd"):

        result = subprocess.run(
            ["passwd", "-Sa"],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode == 0:

            for line in result.stdout.splitlines():

                fields = line.split()

                if len(fields) >= 2:
                    passwd_status[fields[0]] = fields[1]

    status_rows = []

    for user in users:

        status = passwd_status.get(user.pw_name, "Unknown")

        shell = os.path.basename(user.pw_shell)

        if status in ("L", "LK"):
            account_status = "Password Locked"

        elif status == "NP":
            account_status = "No Password"

        elif status == "P":
            account_status = "Password Set"

        else:
            account_status = "Unknown"

        if shell in ("nologin", "false"):
            account_status += " / Non-login Shell"

        if account_status != "Unknown":
            status_rows.append([
                user.pw_name,
                user.pw_uid,
                account_status,
                user.pw_shell
            ])

    display_table(
        ["Username", "UID", "Account Status", "Shell"],
        status_rows
    )

    # ------------------------------------------------------
    # 19. ACCOUNT AND PASSWORD POLICIES
    # ------------------------------------------------------

    section("19. ACCOUNT AND PASSWORD POLICIES")

    policy_files = [
        "/etc/login.defs",
        "/etc/security/pwquality.conf",
        "/etc/security/faillock.conf",
        "/etc/pam.d/common-password",
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth"
    ]

    for path in policy_files:

        if os.path.isfile(path):

            print(f"\n--- {path} ---")

            content = read_file(path)

            for line in content.splitlines():

                line = line.strip()

                if line and not line.startswith("#"):
                    print(line)

    # ------------------------------------------------------
    # 20. PASSWORD AGING INFORMATION
    # ------------------------------------------------------

    section("20. PASSWORD AGING INFORMATION")

    if shutil.which("chage"):

        current_user = os.environ.get("USER", "")

        print(run_command([
            "chage",
            "-l",
            current_user
        ]))

    else:
        print("chage utility unavailable.")

    # ------------------------------------------------------
    # 21. LOGIN AND LOGOUT HISTORY
    # ------------------------------------------------------

    section("21. LOGIN AND LOGOUT HISTORY")

    print("Recent Login History:")
    print(run_command(["last", "-n", "20"]))

    print("\nLast Login Per Account:")
    print(run_command(["lastlog"]))

    print("\nFailed Login History:")

    if shutil.which("lastb"):
        print(run_command(["lastb", "-n", "20"]))
    else:
        print("lastb utility unavailable.")

    # ------------------------------------------------------
    # 22. DOMAIN USER ACCOUNTS
    # ------------------------------------------------------

    section("22. DOMAIN USER ACCOUNTS")

    print("NSS Account Lookup:")
    print(run_command(["getent", "passwd"]))

    if shutil.which("realm"):

        print("\nDomain Configuration:")
        print(run_command(["realm", "list"]))

    if shutil.which("sssctl"):

        print("\nSSSD Domain Information:")
        print(run_command(["sssctl", "domain-list"]))


# ==========================================================
#          3. PRIVILEGE AND PERMISSION INFORMATION
# ==========================================================

def privilege_permission_information():

    # ------------------------------------------------------
    # 23. CURRENT SECURITY CONTEXT
    # ------------------------------------------------------

    section("23. CURRENT SECURITY CONTEXT")

    print("Current User       :", run_command(["whoami"]))
    print("Current UID/GID    :", run_command(["id"]))
    print("Effective UID      :", os.geteuid())
    print("Effective GID      :", os.getegid())
    print("Process ID         :", os.getpid())
    print("Parent Process ID  :", os.getppid())

    if os.geteuid() == 0:
        print("Security Context   : ROOT")
    else:
        print("Security Context   : STANDARD USER")

    # ------------------------------------------------------
    # 24. CURRENT USER PRIVILEGES
    # ------------------------------------------------------

    section("24. CURRENT USER PRIVILEGES")

    print("Username           :", run_command(["whoami"]))
    print("User ID            :", run_command(["id", "-u"]))
    print("Group ID           :", run_command(["id", "-g"]))
    print("Group Memberships  :", run_command(["id", "-Gn"]))

    print("\nCurrent Capabilities:")

    if shutil.which("capsh"):
        print(run_command(["capsh", "--print"]))
    else:
        print("capsh utility unavailable.")

    # ------------------------------------------------------
    # 25. ADMINISTRATIVE PERMISSIONS
    # ------------------------------------------------------

    section("25. ADMINISTRATIVE PERMISSIONS")

    print("Sudo Availability:")

    if shutil.which("sudo"):
        print("Sudo is installed.")

        print("\nCurrent User Sudo Permissions:")

        print(run_command(["sudo", "-n", "-l"]))

    else:
        print("Sudo is not installed.")

    print("\nAdministrator Groups:")

    for group_name in ["sudo", "wheel", "admin"]:

        try:
            group = grp.getgrnam(group_name)

            print(
                f"{group.gr_name}: "
                f"{', '.join(group.gr_mem) or 'No direct members'}"
            )

        except KeyError:
            continue

    # ------------------------------------------------------
    # 26. ROOT ACCESS INFORMATION
    # ------------------------------------------------------

    section("26. ROOT ACCESS INFORMATION")

    print("Current Process Running As Root:",
          "YES" if os.geteuid() == 0 else "NO")

    print("Root Account UID:", pwd.getpwnam("root").pw_uid)

    root_home = os.path.expanduser("~root")

    print("Root Home Directory:", root_home)

    print("Root Directory Permissions:")

    try:
        permissions = stat.filemode(os.stat("/").st_mode)
        print(permissions)
    except OSError:
        print("Unable to inspect root directory.")

    # ------------------------------------------------------
    # 27. LINUX SECURITY AND ACCESS CONTROL CONFIGURATION
    # ------------------------------------------------------

    section("27. LINUX SECURITY CONFIGURATION")

    security_files = [
        "/etc/sudoers",
        "/etc/login.defs",
        "/etc/security/limits.conf",
        "/etc/pam.d/su",
        "/etc/pam.d/sudo"
    ]

    for path in security_files:

        if os.path.exists(path):

            print(f"\nConfiguration: {path}")

            try:
                info = os.stat(path)

                print(
                    "Permissions:",
                    stat.filemode(info.st_mode)
                )

                print("Owner UID:", info.st_uid)
                print("Group GID:", info.st_gid)

            except OSError:
                print("Permission information unavailable.")

    print("\nMandatory Access Control:")

    if shutil.which("getenforce"):
        print("SELinux:", run_command(["getenforce"]))

    if os.path.exists("/sys/module/apparmor"):
        print("AppArmor: Available")
    else:
        print("AppArmor: Not detected")

    # ------------------------------------------------------
    # 28. FILE AND DIRECTORY PERMISSIONS
    # ------------------------------------------------------

    section("28. FILE AND DIRECTORY PERMISSIONS")

    paths = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers",
        "/etc/ssh",
        "/root",
        "/home",
        "/tmp",
        "/var/log"
    ]

    rows = []

    for path in paths:

        if os.path.exists(path):

            try:
                info = os.stat(path)

                rows.append([
                    path,
                    stat.filemode(info.st_mode),
                    info.st_uid,
                    info.st_gid
                ])

            except OSError:
                continue

    display_table(
        ["Path", "Permissions", "Owner UID", "Group GID"],
        rows
    )

    # ------------------------------------------------------
    # 29. SERVICE PERMISSIONS
    # ------------------------------------------------------

    section("29. SERVICE PERMISSIONS")

    if shutil.which("systemctl"):

        print("Running Services:")

        print(run_command([
            "systemctl",
            "list-units",
            "--type=service",
            "--state=running",
            "--no-pager",
            "--no-legend"
        ]))

        print("\nService Manager:")

        print(run_command([
            "systemctl",
            "show",
            "--property=ControlGroup",
            "--property=User",
            "--property=Group",
            "--property=FragmentPath",
            "ssh.service"
        ]))

    else:
        print("systemctl unavailable.")

    # ------------------------------------------------------
    # 30. SCHEDULED TASK PERMISSIONS
    # ------------------------------------------------------

    section("30. SCHEDULED TASK PERMISSIONS")

    cron_paths = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly"
    ]

    rows = []

    for path in cron_paths:

        if os.path.exists(path):

            try:
                info = os.stat(path)

                rows.append([
                    path,
                    stat.filemode(info.st_mode),
                    info.st_uid,
                    info.st_gid
                ])

            except OSError:
                continue

    display_table(
        ["Scheduled Task Path", "Permissions", "Owner UID", "Group GID"],
        rows
    )

    print("\nCurrent User Crontab:")

    if shutil.which("crontab"):
        print(run_command(["crontab", "-l"]))
    else:
        print("crontab utility unavailable.")

    # ------------------------------------------------------
    # 31. ACCESS CONTROL LISTS (ACL)
    # ------------------------------------------------------

    section("31. ACCESS CONTROL LISTS (ACL)")

    if shutil.which("getfacl"):

        acl_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/home",
            "/tmp"
        ]

        for path in acl_paths:

            if os.path.exists(path):

                print(f"\nACL Information: {path}")

                print(run_command([
                    "getfacl",
                    "-p",
                    path
                ]))

    else:
        print("getfacl utility unavailable.")
        print("Install the acl package to inspect ACL information.")

    # ------------------------------------------------------
    # 32. SENSITIVE RESOURCE PERMISSIONS
    # ------------------------------------------------------

    section("32. SENSITIVE RESOURCE PERMISSIONS")

    sensitive_paths = [
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/ssh",
        "/root",
        "/var/log/auth.log",
        "/var/log/secure"
    ]

    rows = []

    for path in sensitive_paths:

        if os.path.exists(path):

            try:
                info = os.stat(path)

                rows.append([
                    path,
                    stat.filemode(info.st_mode),
                    info.st_uid,
                    info.st_gid,
                    os.access(path, os.R_OK)
                ])

            except OSError:
                continue

    display_table(
        [
            "Sensitive Resource",
            "Permissions",
            "Owner UID",
            "Group GID",
            "Readable By Current Process"
        ],
        rows
    )

    print("\nNote: Readability is evaluated for the current process.")
    print("ACLs, capabilities and mandatory access controls may")
    print("also affect effective access.")

# ==========================================================
#          4. Network Information
# ==========================================================

def get_network_information():

    print("\n" + "=" * 60)
    print("          NETWORK INFORMATION REPORT")
    print("=" * 60)

    # 1. Hostname
    print("\n[+] HOST INFORMATION")
    print("Hostname:", socket.gethostname())
    print("Operating System:", platform.system())
    print("Platform:", platform.platform())

    # 2. Network interfaces and IP/MAC addresses
    print("\n[+] NETWORK INTERFACES")

    interfaces = psutil.net_if_addrs()

    for interface, addresses in interfaces.items():
        print(f"\nInterface: {interface}")

        for address in addresses:
            if address.family == socket.AF_INET:
                print("  IPv4 Address:", address.address)
                print("  Subnet Mask:", address.netmask)

            elif address.family == socket.AF_INET6:
                print("  IPv6 Address:", address.address)

            elif address.family == psutil.AF_LINK:
                print("  MAC Address:", address.address)

    # 3. Default gateway and routing information
    print("\n[+] ROUTING INFORMATION")

    system = platform.system()

    command = (
        ["route", "print"]
        if system == "Windows"
        else ["ip", "route"]
    )

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )
        print(result.stdout or "No routing information available.")
    except (OSError, subprocess.SubprocessError) as error:
        print("Routing error:", error)

    # 4. DNS information
    print("\n[+] DNS CONFIGURATION")

    if system == "Windows":
        command = ["ipconfig", "/all"]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10
            )
            for line in result.stdout.splitlines():
                if any(word in line.lower() for word in [
                    "dns servers", "connection-specific dns suffix"
                ]):
                    print(line.strip())
        except (OSError, subprocess.SubprocessError) as error:
            print(error)

    else:
        try:
            with open("/etc/resolv.conf") as file:
                for line in file:
                    if line.startswith(("nameserver", "search", "domain")):
                        print(line.strip())
        except OSError as error:
            print(error)

    # 5. Active network connections
    print("\n[+] ACTIVE NETWORK CONNECTIONS")

    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != psutil.CONN_LISTEN:
                print(
                    "Local:", conn.laddr,
                    "| Remote:", conn.raddr,
                    "| Status:", conn.status
                )
    except psutil.AccessDenied:
        print("Permission denied. Run with appropriate privileges.")

    # 6. Listening ports
    print("\n[+] LISTENING PORTS")

    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == psutil.CONN_LISTEN:
                print(
                    "Address:", conn.laddr,
                    "| PID:", conn.pid
                )
    except psutil.AccessDenied:
        print("Permission denied.")

    # 7. VPN interfaces
    print("\n[+] POSSIBLE VPN INTERFACES")

    keywords = ("tun", "tap", "vpn", "wg", "utun", "ppp")

    found = False

    for interface in interfaces:
        if any(word in interface.lower() for word in keywords):
            print(interface)
            found = True

    if not found:
        print("No recognizable VPN interface found.")

    # 8. Proxy configurations
    print("\n[+] PROXY CONFIGURATION")

    import os

    proxies = {
        key: value for key, value in os.environ.items()
        if "proxy" in key.lower()
    }

    if proxies:
        for key, value in proxies.items():
            print(key, ":", value)
    else:
        print("No proxy environment variables found.")

    print("\n" + "=" * 60)
    print("       NETWORK INFORMATION COLLECTION COMPLETE")
    print("=" * 60)


def run_command(command):
    """Run a local system information command."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=20
        )
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "Information unavailable."


def get_process_service_software():

    system = platform.system()

    print("\n" + "=" * 70)
    print("       RUNNING PROCESSES, SERVICES & INSTALLED SOFTWARE")
    print("=" * 70)

    # -------------------------------------------------
    # 1. RUNNING PROCESSES
    # -------------------------------------------------

    print("\n[+] RUNNING PROCESSES")

    for process in psutil.process_iter(
        ["pid", "name", "username", "status"]
    ):
        try:
            info = process.info

            print(
                f"PID: {info['pid']} | "
                f"Name: {info['name']} | "
                f"Owner: {info['username']} | "
                f"Status: {info['status']}"
            )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # -------------------------------------------------
    # 2. INSTALLED SERVICES
    # -------------------------------------------------

    print("\n[+] INSTALLED SERVICES")

    if system == "Windows":

        output = run_command([
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_Service | "
            "Select-Object Name,DisplayName,State,StartMode,StartName | "
            "Format-Table -AutoSize"
        ])

        print(output)

    elif system == "Linux":

        output = run_command([
            "systemctl",
            "list-unit-files",
            "--type=service",
            "--no-pager"
        ])

        print(output)

    elif system == "Darwin":

        print(run_command(["launchctl", "list"]))

    # -------------------------------------------------
    # 3. SERVICE CONFIGURATIONS AND SERVICE ACCOUNTS
    # -------------------------------------------------

    print("\n[+] SERVICE CONFIGURATIONS")

    if system == "Windows":

        output = run_command([
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_Service | "
            "Select-Object Name,StartName,StartMode,PathName,State | "
            "Format-List"
        ])

        print(output)

    elif system == "Linux":

        print(run_command([
            "systemctl",
            "list-units",
            "--type=service",
            "--all",
            "--no-pager"
        ]))

    # -------------------------------------------------
    # 4. STARTUP SERVICES
    # -------------------------------------------------

    print("\n[+] STARTUP SERVICES")

    if system == "Windows":

        print(run_command([
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_Service | "
            "Where-Object {$_.StartMode -eq 'Auto'} | "
            "Select-Object Name,StartName,State | "
            "Format-Table -AutoSize"
        ]))

    elif system == "Linux":

        print(run_command([
            "systemctl",
            "list-unit-files",
            "--type=service",
            "--state=enabled",
            "--no-pager"
        ]))

    # -------------------------------------------------
    # 5. SCHEDULED TASKS
    # -------------------------------------------------

    print("\n[+] SCHEDULED TASKS")

    if system == "Windows":

        print(run_command([
            "schtasks",
            "/Query",
            "/FO",
            "TABLE"
        ]))

    elif system == "Linux":

        print(run_command(["crontab", "-l"]))

        print("\nSystem scheduled jobs:")
        print(run_command([
            "systemctl",
            "list-timers",
            "--all",
            "--no-pager"
        ]))

    elif system == "Darwin":

        print(run_command(["crontab", "-l"]))

    # -------------------------------------------------
    # 6. BACKGROUND APPLICATIONS
    # -------------------------------------------------

    print("\n[+] BACKGROUND APPLICATIONS")

    for process in psutil.process_iter(["pid", "name", "username"]):
        try:
            print(
                "PID:", process.info["pid"],
                "| Application:", process.info["name"],
                "| User:", process.info["username"]
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # -------------------------------------------------
    # 7. SECURITY SOFTWARE PROCESSES
    # -------------------------------------------------

    print("\n[+] SECURITY SOFTWARE PROCESSES")

    security_keywords = [
        "defender", "antivirus", "security",
        "crowdstrike", "falcon", "sentinel",
        "sophos", "eset", "malwarebytes",
        "mcafee", "kaspersky", "trendmicro",
        "carbonblack"
    ]

    for process in psutil.process_iter(["pid", "name"]):
        try:
            name = (process.info["name"] or "").lower()

            if any(word in name for word in security_keywords):
                print(
                    "PID:", process.info["pid"],
                    "| Process:", process.info["name"]
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # -------------------------------------------------
    # 8. DATABASE PROCESSES
    # -------------------------------------------------

    print("\n[+] DATABASE PROCESSES")

    database_keywords = [
        "mysql", "mysqld", "postgres",
        "postgresql", "mongod", "redis",
        "sqlservr", "oracle", "cassandra"
    ]

    for process in psutil.process_iter(["pid", "name"]):
        try:
            name = (process.info["name"] or "").lower()

            if any(word in name for word in database_keywords):
                print(
                    "PID:", process.info["pid"],
                    "| Database:", process.info["name"]
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # -------------------------------------------------
    # 9. WEB SERVER PROCESSES
    # -------------------------------------------------

    print("\n[+] WEB SERVER PROCESSES")

    web_keywords = [
        "nginx", "apache", "httpd",
        "iis", "w3wp", "tomcat",
        "node", "gunicorn", "uwsgi"
    ]

    for process in psutil.process_iter(["pid", "name"]):
        try:
            name = (process.info["name"] or "").lower()

            if any(word in name for word in web_keywords):
                print(
                    "PID:", process.info["pid"],
                    "| Web Server:", process.info["name"]
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # -------------------------------------------------
    # 10. INSTALLED SOFTWARE
    # -------------------------------------------------

    print("\n[+] INSTALLED APPLICATIONS")

    if system == "Windows":

        output = run_command([
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-ItemProperty "
            "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
            "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
            "-ErrorAction SilentlyContinue | "
            "Where-Object {$_.DisplayName} | "
            "Select-Object DisplayName,DisplayVersion,Publisher | "
            "Format-Table -AutoSize"
        ])

        print(output)

    elif system == "Linux":

        if shutil.which("dpkg-query"):
            print(run_command([
                "dpkg-query", "-W",
                "-f=${binary:Package} ${Version}\\n"
            ]))

        elif shutil.which("rpm"):
            print(run_command(["rpm", "-qa"]))

        elif shutil.which("pacman"):
            print(run_command(["pacman", "-Q"]))

    elif system == "Darwin":

        print(run_command([
            "system_profiler",
            "SPApplicationsDataType"
        ]))

    # -------------------------------------------------
    # 11. PACKAGE MANAGERS
    # -------------------------------------------------

    print("\n[+] PACKAGE MANAGERS")

    package_managers = [
        "pip", "pip3", "npm", "yarn",
        "pnpm", "conda", "apt", "apt-get",
        "dnf", "yum", "rpm", "pacman",
        "brew", "choco", "winget"
    ]

    for manager in package_managers:
        path = shutil.which(manager)

        if path:
            print(manager, ":", path)

    # -------------------------------------------------
    # 12. DEVELOPMENT TOOLS
    # -------------------------------------------------

    print("\n[+] DEVELOPMENT TOOLS")

    development_tools = [
        "python", "python3", "java", "javac",
        "gcc", "g++", "git", "node",
        "npm", "docker", "kubectl",
        "go", "rustc", "dotnet"
    ]

    for tool in development_tools:
        path = shutil.which(tool)

        if path:
            print(tool, ":", path)

    # -------------------------------------------------
    # 13. REMOTE ADMINISTRATION TOOLS
    # -------------------------------------------------

    print("\n[+] REMOTE ADMINISTRATION TOOLS")

    remote_tools = [
        "ssh", "sshd", "mstsc", "AnyDesk",
        "TeamViewer", "vncserver",
        "rustdesk", "remmina"
    ]

    for process in psutil.process_iter(["pid", "name"]):
        try:
            name = (process.info["name"] or "").lower()

            if any(tool.lower() in name for tool in remote_tools):
                print(
                    "PID:", process.info["pid"],
                    "| Tool:", process.info["name"]
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # -------------------------------------------------
    # 14. BACKUP APPLICATIONS
    # -------------------------------------------------

    print("\n[+] BACKUP APPLICATIONS")

    backup_keywords = [
        "veeam", "acronis", "backup",
        "duplicati", "restic", "borg",
        "crashplan", "rubrik", "commvault"
    ]

    for process in psutil.process_iter(["pid", "name"]):
        try:
            name = (process.info["name"] or "").lower()

            if any(word in name for word in backup_keywords):
                print(
                    "PID:", process.info["pid"],
                    "| Backup:", process.info["name"]
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # -------------------------------------------------
    # 15. VPN CLIENTS
    # -------------------------------------------------

    print("\n[+] VPN CLIENTS")

    vpn_keywords = [
        "openvpn", "wireguard", "tailscale",
        "zerotier", "globalprotect", "anyconnect",
        "forticlient", "nordvpn", "expressvpn"
    ]

    for process in psutil.process_iter(["pid", "name"]):
        try:
            name = (process.info["name"] or "").lower()

            if any(word in name for word in vpn_keywords):
                print(
                    "PID:", process.info["pid"],
                    "| VPN:", process.info["name"]
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # -------------------------------------------------
    # 16. SOFTWARE LICENSING INFORMATION
    # -------------------------------------------------

    print("\n[+] SOFTWARE LICENSING INFORMATION")

    if system == "Windows":

        print(run_command([
            "cscript",
            "//Nologo",
            os.path.join(
                os.environ.get("SystemRoot", r"C:\Windows"),
                "System32",
                "slmgr.vbs"
            ),
            "/dli"
        ]))

    else:
        print(
            "Detailed software licensing information "
            "is not available through this general inventory."
        )

    print("\n" + "=" * 70)
    print("       SYSTEM INVENTORY COLLECTION COMPLETED")
    print("=" * 70)

def files_and_credentials_inventory():

    print("\n" + "=" * 75)
    print("       FILES, DATA & CREDENTIALS SECURITY INVENTORY")
    print("=" * 75)

    home = Path.home()

    # -------------------------------------------------
    # FILE CATEGORIES
    # -------------------------------------------------

    categories = {
        "Documents and Spreadsheets": [
            ".doc", ".docx", ".xls", ".xlsx",
            ".csv", ".ppt", ".pptx", ".odt"
        ],

        "PDF Files": [".pdf"],

        "Source Code": [
            ".py", ".java", ".c", ".cpp", ".js",
            ".html", ".css", ".php", ".go",
            ".rs", ".sql", ".sh"
        ],

        "Configuration Files": [
            ".conf", ".cfg", ".ini", ".yaml",
            ".yml", ".toml", ".xml"
        ],

        "Database Files": [
            ".db", ".sqlite", ".sqlite3",
            ".mdb", ".accdb"
        ],

        "Application Logs": [
            ".log"
        ],

        "Backup Files": [
            ".bak", ".backup", ".old", ".dump"
        ],

        "Financial Records": [
            ".qif", ".ofx", ".qfx"
        ]
    }

    results = defaultdict(list)

    # -------------------------------------------------
    # SENSITIVE FILE INDICATORS
    # -------------------------------------------------

    sensitive_keywords = {
        "Customer Information": [
            "customer", "client", "customer_data"
        ],

        "Employee Information": [
            "employee", "staff", "payroll", "hr_data"
        ],

        "Financial Records": [
            "financial", "bank", "invoice",
            "salary", "tax", "payment"
        ],

        "Intellectual Property": [
            "proprietary", "confidential",
            "intellectual", "trade_secret"
        ],

        "SSH Configuration": [
            "authorized_keys", "known_hosts",
            "config"
        ],

        "Cloud Configuration": [
            "credentials", "cloud", "aws",
            "azure", "gcloud"
        ],

        "API Configuration": [
            "api", "token", "secret",
            "auth", "credentials"
        ]
    }

    # Directories excluded from the inventory
    excluded_directories = {
        "node_modules",
        "__pycache__",
        ".git",
        ".cache",
        "venv",
        ".venv",
        "site-packages"
    }

    print("\n[1] FILES AND DATA INVENTORY")
    print("-" * 75)

    total_files = 0
    max_files = 20000

    try:
        for root, dirs, files in os.walk(home):

            dirs[:] = [
                directory for directory in dirs
                if directory not in excluded_directories
            ]

            for filename in files:

                if total_files >= max_files:
                    break

                filepath = Path(root) / filename

                try:
                    if not filepath.is_file():
                        continue

                    size = filepath.stat().st_size
                    extension = filepath.suffix.lower()

                    total_files += 1

                    for category, extensions in categories.items():
                        if extension in extensions:
                            results[category].append(
                                (filepath, size)
                            )

                    # Sensitive filename indicators
                    lower_name = filename.lower()

                    for category, keywords in sensitive_keywords.items():
                        if any(word in lower_name for word in keywords):
                            results[category].append(
                                (filepath, size)
                            )

                except (OSError, PermissionError):
                    continue

            if total_files >= max_files:
                break

    except (OSError, PermissionError) as error:
        print("Directory access error:", error)

    # -------------------------------------------------
    # DISPLAY FILE CATEGORIES
    # -------------------------------------------------

    for category, files in results.items():

        print(f"\n[+] {category}")
        print("-" * 60)

        if files:
            for filepath, size in files:
                print(f"File: {filepath}")
                print(f"Size: {size:,} bytes")
        else:
            print("No matching files found.")

        print("Total:", len(files))

    print("\nTotal files examined:", total_files)

    # -------------------------------------------------
    # 2. CREDENTIALS AND AUTHENTICATION AUDIT
    # -------------------------------------------------

    print("\n\n[2] CREDENTIALS & AUTHENTICATION AUDIT")
    print("-" * 75)

    credential_files = {
        "SSH Private Key Indicators": [
            "id_rsa", "id_ed25519", "id_ecdsa"
        ],

        "Password Manager Files": [
            ".kdbx", ".psafe3", ".1pif"
        ],

        "Cloud Credential Files": [
            "credentials",
            "config"
        ],

        "Kerberos Ticket Indicators": [
            ".ccache", ".kirbi"
        ],

        "Certificate Files": [
            ".pem", ".crt", ".cer", ".p12", ".pfx"
        ],

        "Private Key Files": [
            ".key"
        ],

        "Browser Profile Indicators": [
            "login data",
            "logins.json",
            "cookies.sqlite",
            "web data"
        ],

        "Authentication Configuration": [
            ".netrc",
            ".npmrc",
            ".pypirc"
        ]
    }

    credential_results = defaultdict(list)

    # Check common local credential locations
    for root, dirs, files in os.walk(home):

        dirs[:] = [
            d for d in dirs
            if d not in excluded_directories
        ]

        for filename in files:

            filepath = Path(root) / filename
            lower_name = filename.lower()
            lower_path = str(filepath).lower()

            for category, indicators in credential_files.items():

                matched = any(
                    indicator in lower_name
                    for indicator in indicators
                )

                # Browser storage filenames may be in profile directories
                if category == "Browser Profile Indicators":
                    matched = matched or (
                        any(x in lower_name for x in indicators)
                    )

                if matched:
                    try:
                        credential_results[category].append(filepath)
                    except OSError:
                        pass

    # -------------------------------------------------
    # DISPLAY CREDENTIAL FILE INDICATORS
    # -------------------------------------------------

    for category, files in credential_results.items():

        print(f"\n[+] {category}")
        print("-" * 60)

        if files:
            for filepath in files:
                try:
                    file_stat = filepath.stat()

                    print("File:", filepath)

                    # Display permissions on Unix-like systems
                    if os.name != "nt":
                        permissions = stat.filemode(
                            file_stat.st_mode
                        )
                        print("Permissions:", permissions)

                except OSError:
                    continue
        else:
            print("No matching files found.")

        print("Total detected:", len(files))

    # -------------------------------------------------
    # 3. ENVIRONMENT VARIABLE AUDIT
    # -------------------------------------------------

    print("\n\n[3] ENVIRONMENT VARIABLE SECURITY AUDIT")
    print("-" * 75)

    sensitive_env_keywords = [
        "PASSWORD",
        "SECRET",
        "TOKEN",
        "API_KEY",
        "ACCESS_KEY",
        "CREDENTIAL",
        "AUTH",
        "PRIVATE_KEY",
        "DATABASE_URL"
    ]

    found_variables = []

    for variable in os.environ:

        if any(
            keyword in variable.upper()
            for keyword in sensitive_env_keywords
        ):
            found_variables.append(variable)

    if found_variables:

        for variable in sorted(found_variables):
            print(f"{variable} = [VALUE REDACTED]")

    else:
        print("No matching environment variable names found.")

    print("\nSensitive variable names detected:",
          len(found_variables))

    # -------------------------------------------------
    # 4. SSH CONFIGURATION PERMISSIONS
    # -------------------------------------------------

    print("\n\n[4] SSH CONFIGURATION SECURITY")
    print("-" * 75)

    ssh_directory = home / ".ssh"

    if ssh_directory.exists():

        print("SSH directory:", ssh_directory)

        for filename in [
            "config",
            "authorized_keys",
            "known_hosts",
            "id_rsa",
            "id_ed25519"
        ]:

            filepath = ssh_directory / filename

            if filepath.exists():

                print("\nFile:", filename)

                try:
                    file_stat = filepath.stat()

                    if os.name != "nt":

                        permissions = stat.S_IMODE(
                            file_stat.st_mode
                        )

                        print(
                            "Permissions:",
                            oct(permissions)
                        )

                        if filename.startswith("id_"):
                            if permissions & 0o077:
                                print(
                                    "WARNING: Private key permissions "
                                    "may be too permissive."
                                )
                            else:
                                print(
                                    "Private key permissions: "
                                    "No group/other access detected."
                                )

                    else:
                        print(
                            "Windows ACL details require "
                            "a separate permission audit."
                        )

                except OSError as error:
                    print("Permission check unavailable:", error)

    else:
        print("SSH directory not found.")

    # -------------------------------------------------
    # 5. CLOUD AND API CONFIGURATION INDICATORS
    # -------------------------------------------------

    print("\n\n[5] CLOUD & API CONFIGURATION")
    print("-" * 75)

    cloud_locations = [
        home / ".aws",
        home / ".azure",
        home / ".config" / "gcloud",
        home / ".kube",
        home / ".docker"
    ]

    for location in cloud_locations:

        if location.exists():

            print("[FOUND]", location)

        else:

            print("[NOT FOUND]", location)

    # -------------------------------------------------
    # 6. DATABASE CONFIGURATION INDICATORS
    # -------------------------------------------------

    print("\n\n[6] DATABASE CONFIGURATION")
    print("-" * 75)

    database_locations = [
        home / ".my.cnf",
        home / ".pgpass",
        home / ".pg_service.conf",
        home / ".mongorc.js"
    ]

    for filepath in database_locations:

        if filepath.exists():

            print("[FOUND]", filepath)

            try:
                if os.name != "nt":
                    permissions = stat.S_IMODE(
                        filepath.stat().st_mode
                    )
                    print("Permissions:", oct(permissions))

            except OSError:
                pass

    # -------------------------------------------------
    # 7. SESSION AND AUTHENTICATION INDICATORS
    # -------------------------------------------------

    print("\n\n[7] SESSION & AUTHENTICATION INDICATORS")
    print("-" * 75)

    session_locations = [
        home / ".config",
        home / ".local" / "share",
        home / "AppData" / "Local"
    ]

    for location in session_locations:

        if location.exists():
            print("[FOUND DIRECTORY]", location)

    # -------------------------------------------------
    # FINAL REPORT
    # -------------------------------------------------

    print("\n" + "=" * 75)
    print("       FILES & CREDENTIALS AUDIT COMPLETED")
    print("=" * 75)

    print("Operating System:", platform.system())
    print("Home Directory:", home)
    print("Files Examined:", total_files)
    print("Credential Indicator Categories:",
          len(credential_results))
    print("Environment Variable Names Detected:",
          len(found_variables))

    print("\nNOTE:")
    print("This inventory identifies file and configuration")
    print("indicators only. It does not extract or display secrets.")
    print("=" * 75)
# ==========================================================
#                       MAIN FUNCTION
# ==========================================================

def main():

    print("\n")

    print("*" * 80)
    print("       LINUX SYSTEM & SECURITY INFORMATION GATHERING")
    print("*" * 80)

    system_information()

    user_account_information()

    privilege_permission_information()
    get_network_information()
    get_process_service_software()
    files_and_credentials_inventory()
    print("\n")

    print("*" * 80)
    print("          INFORMATION COLLECTION COMPLETED")
    print("*" * 80)


if __name__ == "__main__":
    main()
