#!/bin/bash
timedatectl set-timezone Asia/Jakarta
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
export SCRIPT_SERVER="https://raw.githubusercontent.com/Serarinne/tester/main"
export IP_SERVER=$(wget -qO- ipv4.icanhazip.com)

clear
echo -e "-----------------------------------------"
echo -e "|          Pengaturan Server            |"
echo -e "-----------------------------------------"
echo -e ""
read -rp "Nama Server        : " SERVER_NAME
read -rp "Domain Server      : " SERVER_DOMAIN
mkdir /root/serarinne
rm -f /root/serarinne/name
rm -f /root/serarinne/domain
rm -f /root/serarinne/bug
rm -f /root/serarinne/cloudflare
rm -f /root/serarinne/ip
echo $SERVER_NAME > /root/serarinne/name
echo $SERVER_DOMAIN > /root/serarinne/domain
echo $SERVER_IP > /root/serarinne/ip

clear
echo -e "-----------------------------------------"
echo -e "|        Pencopotan Package Lama        |"
echo -e "-----------------------------------------"
apt-get remove --purge nginx* nginx-common* nginx-full* dropbear* stunnel4* apache2* ufw* firewalld* exim4* -y
apt autoremove -y

clear
echo -e "-----------------------------------------"
echo -e "|           Instalasi Package           |"
echo -e "-----------------------------------------"
apt update -y
apt install sudo dpkg psmisc ruby wondershaper nmap wget vim nano gnupg1 apt-transport-https gcc g++ automake make autoconf perl m4 dos2unix iptables iptables-persistent libreadline-dev zlib1g-dev libssl-dev python3 screen curl jq bzip2 gzip coreutils rsyslog iftop htop zip unzip net-tools sed gnupg bc build-essential dirmngr libxml-parser-perl neofetch screenfetch git lsof openssl easy-rsa fail2ban tmux vnstat dropbear libsqlite3-dev socat cron bash-completion ntpdate xz-utils  gnupg2 dnsutils lsb-release chrony lolcat -y

clear
echo -e "-----------------------------------------"
echo -e "|            Instalasi SSH WS           |"
echo -e "-----------------------------------------"
wget -q -O /etc/pam.d/common-password "${SCRIPT_SERVER}/common-password" && chmod +x /etc/pam.d/common-password
wget -q -O /usr/local/bin/ssh-ws "${SCRIPT_SERVER}/ssh-ws" && chmod +x /usr/local/bin/ssh-ws
cat > /etc/systemd/system/ssh-ws.service << END
[Unit]
Description=SSH Websocket
Documentation=https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python2 -O /usr/local/bin/ssh-ws
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

systemctl daemon-reload >/dev/null 2>&1
systemctl enable ssh-ws >/dev/null 2>&1
systemctl start ssh-ws >/dev/null 2>&1
systemctl restart ssh-ws >/dev/null 2>&1

cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

chmod +x /etc/rc.local
systemctl enable rc-local >/dev/null 2>&1
systemctl start rc-local.service >/dev/null 2>&1

sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

BADVPN_STATUS=`screen -list | awk  '{print $1}' | grep -ow "badvpn" | sort | uniq`
if [ "$BADVPN_STATUS" = "badvpn" ]; then
sleep 1
rm /root/screenlog > /dev/null 2>&1
    ACTIVE_BADVPN=(`screen -list | awk  '{print $1}' | grep -w "badvpn"`)
    for ACTIVED_BADVPN in "${ACTIVE_BADVPN[@]}"
    do
        ACTIVE_BADVPN2=(`screen -list | awk  '{print $1}' | grep -w "badvpn"`)
        if [ "$ACTIVE_BADVPN2" = "$ACTIVED_BADVPN" ]; then
        for DUPLICATE_BADVPN in "${ACTIVE_BADVPN2[@]}"; do
            sleep 1
            screen -XS $DUPLICATE_BADVPN quit > /dev/null 2>&1
        done 
        fi
    done
else
echo -ne
fi

wget -q -O /usr/bin/badvpn-udpgw "${SCRIPT_SERVER}/badvpn" && chmod +x /usr/bin/badvpn-udpgw
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500' /etc/rc.local >/dev/null 2>&1
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500' /etc/rc.local >/dev/null 2>&1
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000' /etc/rc.local >/dev/null 2>&1
systemctl daemon-reload >/dev/null 2>&1
systemctl start rc-local.service >/dev/null 2>&1
systemctl restart rc-local.service >/dev/null 2>&1

sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 2253' /etc/ssh/sshd_config
echo "Port 22" >> /etc/ssh/sshd_config
echo "Port 40000" >> /etc/ssh/sshd_config
echo "X11Forwarding yes" >> /etc/ssh/sshd_config
echo "AllowTcpForwarding yes" >> /etc/ssh/sshd_config
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding yes/g' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
systemctl daemon-reload >/dev/null 2>&1
systemctl start ssh >/dev/null 2>&1
systemctl restart ssh >/dev/null 2>&1

sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109"/g' /etc/default/dropbear
systemctl daemon-reload >/dev/null 2>&1
systemctl start dropbear >/dev/null 2>&1
systemctl restart dropbear >/dev/null 2>&1
VALID_SHELL=$(cat /etc/shells | grep -w "/bin/false")
if [[ "$VALID_SHELL" = "/bin/false" ]];then
  echo -ne
else
  echo "/bin/false" >> /etc/shells
  echo "/usr/sbin/nologin" >> /etc/shells
fi

apt install stunnel4 -y

cat > /etc/stunnel/stunnel.conf <<-END
cert = /usr/local/etc/xray/xray.crt
key = /usr/local/etc/xray/xray.key
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 447
connect = 127.0.0.1:109

[openssh]
accept = 777
connect = 127.0.0.1:22

[openvpn]
accept = 442
connect = 127.0.0.1:1194
END

rm -fr /etc/systemd/system/stunnel4.service
cat > /etc/systemd/system/stunnel4.service << END
[Unit]
Description=Stunnel4 Service
Documentation=https://stunnel.org
After=syslog.target network-online.target

[Service]
ExecStart=stunnel4 /etc/stunnel/stunnel.conf
Type=forking

[Install]
WantedBy=multi-user.target
END

systemctl daemon-reload >/dev/null 2>&1
systemctl enable stunnel4 >/dev/null 2>&1
systemctl start stunnel4 >/dev/null 2>&1
systemctl restart stunnel4 >/dev/null 2>&1

INSERT_SCRIPT(){
	if [ "$(tail -n1 $1 | wc -l)" == "0"  ];then
		echo "" >> "$1"
	fi
	echo "$2" >> "$1"
}

CHECK_SCRIPT(){
	if [ -z "$(cat "$1" | grep "$2")" ];then
		INSERT_SCRIPT "$1" "$2"
	fi
}

if [ -n "$(lsmod | grep bbr)" ];then
  return 1;
else
  modprobe tcp_bbr
  INSERT_SCRIPT "/etc/modules-load.d/modules.conf" "tcp_bbr"
  INSERT_SCRIPT "/etc/sysctl.conf" "net.core.default_qdisc = fq"
  INSERT_SCRIPT "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control = bbr"
  sysctl -p
  if [ -n "$(sysctl net.ipv4.tcp_available_congestion_control | grep bbr)" ] && [ -n "$(sysctl net.ipv4.tcp_congestion_control | grep bbr)" ] && [ -n "$(lsmod | grep "tcp_bbr")" ];then
    echo "Berhasil menginstall TCP_BBR."
  else
    echo "Gagal menginstall TCP_BBR."
  fi
fi

CHECK_SCRIPT "/etc/security/limits.conf" "* soft nofile 51200"
CHECK_SCRIPT "/etc/security/limits.conf" "* hard nofile 51200"
CHECK_SCRIPT "/etc/security/limits.conf" "root soft nofile 51200"
CHECK_SCRIPT "/etc/security/limits.conf" "root hard nofile 51200"
CHECK_SCRIPT "/etc/sysctl.conf" "fs.file-max = 51200"
CHECK_SCRIPT "/etc/sysctl.conf" "net.core.rmem_max = 67108864"
CHECK_SCRIPT "/etc/sysctl.conf" "net.core.wmem_max = 67108864"
CHECK_SCRIPT "/etc/sysctl.conf" "net.core.netdev_max_backlog = 250000"
CHECK_SCRIPT "/etc/sysctl.conf" "net.core.somaxconn = 4096"
CHECK_SCRIPT "/etc/sysctl.conf" "net.ipv4.tcp_syncookies = 1"
CHECK_SCRIPT "/etc/sysctl.conf" "net.ipv4.tcp_tw_reuse = 1"
CHECK_SCRIPT "/etc/sysctl.conf" "net.ipv4.tcp_fin_timeout = 30"
CHECK_SCRIPT "/etc/sysctl.conf" "net.ipv4.tcp_keepalive_time = 1200"
CHECK_SCRIPT "/etc/sysctl.conf" "net.ipv4.ip_local_port_range = 10000 65000"
CHECK_SCRIPT "/etc/sysctl.conf" "net.ipv4.tcp_max_syn_backlog = 8192"
CHECK_SCRIPT "/etc/sysctl.conf" "net.ipv4.tcp_max_tw_buckets = 5000"
CHECK_SCRIPT "/etc/sysctl.conf" "net.ipv4.tcp_fastopen = 3"
CHECK_SCRIPT "/etc/sysctl.conf" "net.ipv4.tcp_mem = 25600 51200 102400"
CHECK_SCRIPT "/etc/sysctl.conf" "net.ipv4.tcp_rmem = 4096 87380 67108864"
CHECK_SCRIPT "/etc/sysctl.conf" "net.ipv4.tcp_wmem = 4096 65536 67108864"
CHECK_SCRIPT "/etc/sysctl.conf" "net.ipv4.tcp_mtu_probing = 1"
sleep 1

rm -fr /usr/local/ddos
mkdir -p /usr/local/ddos >/dev/null 2>&1
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos  >/dev/null 2>&1
sleep 1
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1

sudo iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
sudo iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
sudo iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
sudo iptables-save > /etc/iptables.up.rules
sudo iptables-restore -t < /etc/iptables.up.rules
sudo netfilter-persistent save >/dev/null 2>&1
sudo netfilter-persistent reload >/dev/null 2>&1

apt autoclean -y >/dev/null 2>&1

if dpkg -s unscd >/dev/null 2>&1; then
  apt -y remove --purge unscd >/dev/null 2>&1
fi

cd
systemctl restart cron >/dev/null 2>&1
systemctl restart ssh >/dev/null 2>&1
systemctl restart dropbear >/dev/null 2>&1
systemctl restart fail2ban >/dev/null 2>&1
systemctl restart stunnel4 >/dev/null 2>&1
systemctl restart vnstat >/dev/null 2>&1
sleep 1
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500 >/dev/null 2>&1
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500 >/dev/null 2>&1
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 >/dev/null 2>&1
history -c
echo "unset HISTFILE" >> /etc/profile

clear
echo -e "-----------------------------------------"
echo -e "|         Instalasi XRAY-Core           |"
echo -e "-----------------------------------------"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
rm -f /usr/local/etc/xray/config.json
wget -q -O /usr/local/etc/xray/config.json "${SCRIPT_SERVER}/config.json"
systemctl daemon-reload
systemctl restart xray

clear
echo -e "-----------------------------------------"
echo -e "|         Instalasi Web Server          |"
echo -e "-----------------------------------------"
apt install -y nginx
cd
rm -fr /etc/nginx/sites-enabled/default
rm -fr /etc/nginx/sites-available/default
wget -q -O /etc/nginx/nginx.conf "${SCRIPT_SERVER}/nginx.conf"
wget -q -O /etc/nginx/conf.d/vps.conf "${SCRIPT_SERVER}/vps.conf"

cat >/etc/nginx/conf.d/xray.conf <<EOF
server {
  listen 80;
  listen [::]:80;
  listen 443 ssl http2 reuseport;
  listen [::]:443 http2 reuseport;
  server_name 127.0.0.1 localhost;
  ssl_certificate /usr/local/etc/xray/xray.crt;
  ssl_certificate_key /usr/local/etc/xray/xray.key;
  ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
  ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
  root /var/www/html;

  location / {
    proxy_redirect off;
    proxy_pass http://127.0.0.1:700;
    proxy_http_version 1.1;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $http_host;
  }

  location = /vmess {
    proxy_redirect off;
    proxy_pass http://127.0.0.1:9000;
    proxy_http_version 1.1;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $http_host;
  }
}
EOF

systemctl daemon-reload >/dev/null 2>&1
systemctl restart xray >/dev/null 2>&1
systemctl restart nginx >/dev/null 2>&1

read -p "$( echo -e "Press ${orange}[ ${NC}${green}Enter${NC} ${CYAN}]${NC} For Reboot") "
reboot
