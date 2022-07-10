#!/bin/bash
echo -n "$SERVER_DEPLOY_CERT_B64" | base64 -d | tee /root/.ssh/id_ed25519-cert.pub
echo -n "$SERVER_DEPLOY_PUBLIC_B64" | base64 -d | tee -a /root/.ssh/authorized_keys
echo -n "$TITAN_PUBLIC_KEY" | tee -a /root/.ssh/authorized_keys

# *.ackerson.de SSL cert
mkdir /root/traefik
cat <<EOF >/root/traefik/acme.json
$ACME_JSON
EOF
chmod 600 /root/traefik/acme.json

rmdir /root/traefik/dynamic_conf.yml || true
curl -o /root/traefik/dynamic_conf.yml https://raw.githubusercontent.com/ackersonde/digitaloceans/main/scripts/dynamic_conf.yml

apt-get update && apt-get upgrade

# prepare iptables persistence and unattended-upgrades install settings
debconf-set-selections <<EOF
iptables-persistent iptables-persistent/autosave_v4 boolean true
iptables-persistent iptables-persistent/autosave_v6 boolean true
unattended-upgrades unattended-upgrades/enable_auto_updates boolean true
EOF
dpkg-reconfigure -f noninteractive unattended-upgrades

# now that we've set debconf selections above, we can install iptables-persistent
apt-get -y install docker.io iptables-persistent

cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id} stable";
    "\${distro_id} \${distro_codename}-security";
    "\${distro_id} \${distro_codename}-updates";
};

// Do automatic removal of new unused dependencies after the upgrade
// (equivalent to apt-get autoremove)
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Automatically reboot *WITHOUT CONFIRMATION* if a
// the file /var/run/reboot-required is found after the upgrade
Unattended-Upgrade::Automatic-Reboot "true";
EOF

# setup ipv6 capability in docker
cat > /etc/docker/daemon.json <<EOF
{
  "ipv6": true,
  "fixed-cidr-v6": "fd00::/80"
}
EOF
systemctl start docker
systemctl enable docker

# harden SSH - remove after firewall rules tightened if you'd like
sed -i -e '/^\(#\|\)PasswordAuthentication/s/^.*$/PasswordAuthentication no/' /etc/ssh/sshd_config
# service ssh restart
touch ~/.hushlogin
