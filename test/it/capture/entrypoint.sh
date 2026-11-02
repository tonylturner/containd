#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

serve_dns() {
    cat >/tmp/example.test.zone <<'EOF'
$TTL 60
@ IN SOA ns.example.test. hostmaster.example.test. ( 1 60 60 60 60 )
@ IN NS ns.example.test.
ns IN A 198.51.100.10
www IN A 192.0.2.20
www IN AAAA 2001:db8::20
www IN TXT "recorded fixture"
EOF
    cat >/tmp/named.conf <<'EOF'
options {
    directory "/var/cache/bind";
    listen-on { any; };
    listen-on-v6 { none; };
    allow-query { any; };
    recursion no;
};
zone "example.test" { type master; file "/tmp/example.test.zone"; };
EOF
    exec named -g -c /tmp/named.conf -u bind
}

serve_tls() {
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -keyout /tmp/server.key -out /tmp/server.crt \
        -subj '/CN=tls.example.test' \
        -addext 'subjectAltName=DNS:tls.example.test,DNS:tls12.example.test,DNS:tls13.example.test' \
        >/dev/null 2>&1
    exec openssl s_server -accept 443 -cert /tmp/server.crt -key /tmp/server.key -quiet
}

serve_http() {
    printf '%s\n' 'Disposable capture server' >/var/www/html/index.html
    printf '%s\n' 'ServerName www.example.test' >>/etc/apache2/apache2.conf
    exec apache2ctl -DFOREGROUND
}

serve_ssh() {
    useradd --create-home --shell /bin/sh demo
    printf 'demo:%s\n' "${LAB_PASSWORD:?LAB_PASSWORD is required}" | chpasswd
    ssh-keygen -q -t ed25519 -f /tmp/ssh_host_ed25519_key -N ''
    mkdir -p /run/sshd
    exec /usr/sbin/sshd -D -e \
        -h /tmp/ssh_host_ed25519_key \
        -o PasswordAuthentication=yes \
        -o KbdInteractiveAuthentication=no \
        -o PermitRootLogin=no \
        -o UsePAM=no
}

serve_ntp() {
    cat >/tmp/chrony.conf <<'EOF'
driftfile /tmp/chrony.drift
rtcsync
local stratum 4
allow 198.51.100.0/24
bindaddress 0.0.0.0
EOF
    exec chronyd -d -x -f /tmp/chrony.conf
}

serve_snmp() {
    cat >/tmp/snmpd.conf <<'EOF'
agentAddress udp:0.0.0.0:161
rocommunity public 198.51.100.0/24
sysLocation disposable lab
sysContact operator@example.test
EOF
    exec snmpd -f -Lo -C -c /tmp/snmpd.conf
}

serve_rdp() {
    useradd --create-home --shell /bin/sh demo
    printf 'demo:%s\n' "${LAB_PASSWORD:?LAB_PASSWORD is required}" | chpasswd
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -keyout /tmp/rdp.key -out /tmp/rdp.crt \
        -subj '/CN=rdp.example.test' >/dev/null 2>&1
    chgrp xrdp /tmp/rdp.key
    chmod 0640 /tmp/rdp.key
    sed -i 's#^certificate=.*#certificate=/tmp/rdp.crt#; s#^key_file=.*#key_file=/tmp/rdp.key#' \
        /etc/xrdp/xrdp.ini
    xrdp-sesman --nodaemon >/dev/null 2>&1 &
    exec xrdp --nodaemon
}

serve_smb() {
    mkdir -p /srv/share
    printf '%s\n' 'recorded SMB fixture' >/srv/share/fixture.txt
    cat >/tmp/smb.conf <<'EOF'
[global]
    server role = standalone server
    security = user
    map to guest = Bad User
    server min protocol = SMB2_02
    smb ports = 445
    disable netbios = yes
    load printers = no
    log file = /tmp/samba.log
    [share]
    path = /srv/share
    guest ok = yes
    guest only = yes
    read only = yes
EOF
    exec smbd --foreground --no-process-group --debug-stdout --configfile=/tmp/smb.conf
}

case "${1:-}" in
    serve)
        case "${2:-}" in
            dns) serve_dns ;;
            tls) serve_tls ;;
            http) serve_http ;;
            ssh) serve_ssh ;;
            ntp) serve_ntp ;;
            snmp) serve_snmp ;;
            rdp) serve_rdp ;;
            smb) serve_smb ;;
            *) printf 'unknown server: %s\n' "${2:-}" >&2; exit 2 ;;
        esac
        ;;
    tcpdump|dig|openssl|curl|sshpass|ntpdig|snmpget|snmpwalk|xvfb-run|smbclient|dpkg-query)
        exec "$@"
        ;;
    package-inventory)
        dpkg-query -W -f='${binary:Package}=${Version}\n' | LC_ALL=C sort
        ;;
    license-notices)
        for package in apache2 bind9 bind9-dnsutils chrony curl freerdp2-x11 ntpsec-ntpdate openssh-client openssl python3 samba smbclient snmp snmpd sshpass tcpdump xrdp xvfb; do
            source=${package}
            if [ "$package" = "bind9-dnsutils" ]; then source=bind9.9; fi
            if [ -f "/usr/share/doc/$source/copyright" ]; then
                python3 -c 'import pathlib,re,sys; lines=pathlib.Path(sys.argv[1]).read_text().splitlines(); lines=[re.sub(r"^(?: +\t)+", lambda match: "\t"*match.group(0).count("\t"), line.rstrip()) for line in lines]; pathlib.Path(sys.argv[2]).write_text("\n".join(lines).rstrip()+"\n")' \
                    "/usr/share/doc/$source/copyright" "/licenses/$package.txt"
            fi
        done
        ;;
    *)
        exec "$@"
        ;;
esac
