#!/bin/bash
clear
sysctl -w net.ipv6.conf.all.disable_ipv6=1 
sysctl -w net.ipv6.conf.default.disable_ipv6=1
wget -q https://raw.githubusercontent.com/x-h1/l/master/github -O /root/.gh

# Color
YELLOW="\033[33m"
BLUE="\033[36m"
NC='\e[0m'
KANAN="\033[1;32m<\033[1;33m<\033[1;31m<\033[1;31m$NC"
KIRI="\033[1;32m>\033[1;33m>\033[1;31m>\033[1;31m$NC"

print_pasang() {
if [[ 0 -eq $? ]]; then
echo -e "${BLUE}[XD TUNNEL]${NC}${KIRI}${YELLOW} $1 ${NC}"
sleep 2
fi
}

function checking_vps() {
print_pasang "Mengecek Vps apakah support dengan script"
if [ "${EUID}" -ne 0 ]; then
echo "You need to run this script as root"
exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
echo "OpenVZ is not supported"
exit 1
fi
if [ -f "/etc/xray/domain" ]; then
echo "Script Already Installed"
exit 1
fi
if [[ $( uname -m | awk '{print $1}' ) == "x86_64" ]]; then
echo -e ""
else
echo -e " Your Architecture Is Not Supported ( $( uname -m ) )"
exit 1
fi
# // Checking OS
if [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "ubuntu" ]]; then
echo -e ""
elif [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "debian" ]]; then
echo -e ""
else
echo "Your OS Is Not Supported ( $( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
exit 1
fi
if [ ! -d /root/.info ]; then
mkdir -p /root/.info
curl "ipinfo.io/org?token=7a814b6263b02c" > /root/.info/.isp
curl "ipinfo.io/city?token=7a814b6263b02c" > /root/.info/.city
curl "ipinfo.io/region?token=7a814b6263b02c" > /root/.info/.region
curl "ipinfo.io/timezone?token=7a814b6263b02c" > /root/.info/.timezone
fi
}
source /root/.gh

localip=$(hostname -I | cut -d\  -f1)
hst=( `hostname` )
dart=$(cat /etc/hosts | grep -w `hostname` | awk '{print $2}')
if [[ "$hst" != "$dart" ]]; then
echo "$localip $(hostname)" >> /etc/hosts
fi

function buat_folder() {
print_pasang "Membuat folder folder yang dibutuhkan"
mkdir -p /etc/info
mkdir -p /etc/info/ssh
mkdir -p /etc/info/vmess
mkdir -p /etc/info/vless
mkdir -p /etc/info/trojan
mkdir -p /etc/info/noobzvpns
mkdir -p /etc/xray
mkdir -p /etc/xray/limit
mkdir -p /etc/xray/limit/trojan
mkdir -p /etc/xray/limit/vless
mkdir -p /etc/xray/limit/vmess
mkdir -p /etc/xray/limit/ssh
mkdir -p /etc/xray/limit/ssh/ip
mkdir -p /etc/xray/limit/trojan/ip
mkdir -p /etc/xray/limit/trojan/quota
mkdir -p /etc/xray/limit/vless/ip
mkdir -p /etc/xray/limit/vless/quota
mkdir -p /etc/xray/limit/vmess/ip
mkdir -p /etc/xray/limit/vmess/quota
mkdir -p /home/vps/public_html
mkdir -p /home/vps/public_html/xd
mkdir -p /var/lib/xdxl >/dev/null 2>&1
echo "IP=" >> /var/lib/xdxl/ipvps.conf
touch /etc/xray/domain
touch /etc/info/ssh/akun.conf
touch /etc/info/vmess/akun.conf
touch /etc/info/vless/akun.conf
touch /etc/info/trojan/akun.conf
touch /etc/info/noobzvpns/akun.conf
echo "& Plaguin Account" >> /etc/info/ssh/akun.conf
echo "& Plaguin Account" >> /etc/info/vmess/akun.conf
echo "& Plaguin Account" >> /etc/info/vless/akun.conf
echo "& Plaguin Account" >> /etc/info/trojan/akun.conf
echo "& Plaguin Account" >> /etc/info/noobzvpns/akun.conf
}

function xd_ganteng() {
print_pasang "Memasang Bahan yang di butuhkan"
apt update -y
apt upgrade -y
apt dist-upgrade -y
apt install sudo -y
sudo apt-get clean all
sudo apt-get install -y debconf-utils
apt-get remove --purge ufw firewalld -y
apt-get remove --purge exim4 -y
apt-get autoremove -y
apt install haproxy -y
apt install -y dropbear
apt install -y stunnel4
apt install -y figlet
apt install -y zip unzip gzip bzip2
apt install -y cron
apt install -y nginx
apt install -y ruby
gem install lolcat
apt-get remove --purge ufw firewalld -y
apt-get remove --purge exim4 -y
sudo apt-get install -y --no-install-recommends software-properties-common
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
sudo apt-get install -y iptables iptables-persistent netfilter-persistent php php-fpm php-cli php-mysql libxml-parser-perl squid nmap screen jq coreutils rsyslog iftop net-tools sed gnupg gnupg1 bc apt-transport-https build-essential dirmngr libxml-parser-perl screenfetch lsof openssl openvpn easy-rsa fail2ban tmux squid3 socat bash-completion ntpdate xz-utils gnupg2 dnsutils lsb-release chrony libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev xl2tpd pptpd apt git speedtest-cli p7zip-full
sudo apt-get install -y libjpeg-dev zlib1g-dev python python3 python3-pip shc build-essential speedtest-cli p7zip-full
sudo apt-get autoclean -y >/dev/null 2>&1
audo apt-get -y --purge removd unscd >/dev/null 2>&1
sudo apt-get -y --purge remove samba* >/dev/null 2>&1
sudo apt-get -y --purge remove apache2* >/dev/null 2>&1
sudo apt-get -y --purge remove bind9* >/dev/null 2>&1
sudo apt-get -y remove sendmail* >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
}

function ins_vnstat() {
print_pasang "Installasi vnstat service"
sudo apt-get -y install vnstat
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6
}

function Swap_Gotop() {
print_pasang "Installasi Swap sebesar 1gb"
curl https://raw.githubusercontent.com/xxxserxxx/gotop/master/scripts/download.sh | bash && chmod +x gotop && sudo mv gotop /usr/local/bin/
dd if=/dev/zero of=/swapfile bs=1024 count=1048576
mkswap /swapfile
chown root:root /swapfile
chmod 0600 /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab
# > Singkronisasi jam
chronyd -q 'server 0.id.pool.ntp.org iburst'
chronyc sourcestats -v
chronyc tracking -v
wget ${GITHUB_REPO}/bbr.sh
chmod 777 bbr.sh ; ./bbr.sh
rm -rf bbr.sh
}

function pasang_domain() {
clear
echo -e "\e[1;33mSebelum memasukan domain"
echo -e "harap pointing dulu ip vps kamu !!\e[0m"
echo ""
read -rp "Masukan Domain Kamu : " dom
if [ ! $dom = "" ]; then
echo "$dom" > /etc/xray/domain
echo "$dom" > /root/domain
echo "IP=$dom" > /var/lib/xdxl/ipvps.conf
else
echo -e "Masukan dengan benar !!!"
pasang_domain
fi
}

function password_ssh() {
print_pasang "Installasi service ssh"
# initializing var
export DEBIAN_FRONTEND=noninteractive
MYIP=$(wget -qO- ipinfo.io/ip);
MYIP2="s/xxxxxxxxx/$MYIP/g";
NET=$(ip -o $ANU -4 route show to default | awk '{print $5}');
source /etc/os-release
ver=$VERSION_ID

#detail nama perusahaan
country=ID
state=Indonesia
locality=none
organization=none
organizationalunit=none
commonname=none
email=adamspx17@gmail.com

wget -q ${GITHUB_REPO}/password -O /etc/pam.d/common-password
chmod 777 /etc/pam.d/common-password

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

# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

# Ubah izin akses
chmod +x /etc/rc.local

# enable rc local
systemctl enable rc-local
systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

cd
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
echo "Port 22" >>/etc/ssh/sshd_config
echo "Port 2222" >>/etc/ssh/sshd_config
/etc/init.d/ssh restart
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
}

function sldns() {
print_pasang "Installasi Service Slow DNS"
wget -q ${GITHUB_REPO}/slowdns.sh
chmod 777 slowdns.sh && ./slowdns.sh
mkdir -p /etc/slowdns
cd /etc/slowdns
wget -O dns.zip "${GITHUB_REPO}/dns.zip" >/dev/null 2>&1
unzip dns.zip
chmod +x *
rm -rf dns.zip
./dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
}

function ins_noobz() {
print_pasang "Installasi NoobzVpns Service"
mkdir -p /etc/noobzvpns
cat > /etc/noobzvpns/config.json <<-JSON
{
	"tcp_std": [
		2052
	],
	"tcp_ssl": [
		2053
	],
	"ssl_cert": "/etc/xray/xray.crt",
	"ssl_key": "/etc/xray/xray.key",
	"ssl_version": "AUTO",
	"conn_timeout": 60,
	"dns_resolver": "/etc/resolv.conf",
	"http_ok": "HTTP/1.1 101 Switching Protocols[crlf]Upgrade: websocket[crlf]"
}
JSON

cat > /etc/systemd/system/noobzvpns.service <<-END
[Unit]
Description=NoobzVpn-Server
Wants=network-online.target
After=network.target network-online.target

[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
User=root
Type=simple
TimeoutStopSec=1
LimitNOFILE=infinity
ExecStart=/usr/bin/noobzvpns --start-service

[Install]
WantedBy=multi-user.target

END

wget -O /usr/bin/noobzvpns "https://raw.githubusercontent.com/zhets/ScriptAutoInstall-xdxl/main/noobzvpns.x86_64"
chmod 777 /usr/bin/noobzvpns
}

function konfigurasi_paket() {
print_pasang "Memasang paket konfigurasi"
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
domain=$(cat /etc/xray/domain)
nsdomain=$(cat /etc/xray/dns)
rm -fr /etc/haproxy/haproxy.cfg
wget -O /etc/nginx/nginx.conf ${GITHUB_REPO}/nginx.conf
wget -O /etc/nginx/conf.d/xray.conf ${GITHUB_REPO}/xray.conf
wget -O /etc/nginx/conf.d/vps.conf ${GITHUB_REPO}/vps.conf
sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
wget -O /etc/xray/config.json ${GITHUB_REPO}/config.json
sed -i "s/xxxx/$nsdomain/g" /etc/systemd/system/client.service 
sed -i "s/xxxx/$nsdomain/g" /etc/systemd/system/server.service 

cat > /etc/haproxy/haproxy.cfg <<-END
global
    daemon
    maxconn 256

defaults
    mode tcp
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend ssh-ssl
    bind *:443 ssl crt /etc/haproxy/xdxl.pem
    mode tcp
    option tcplog
    default_backend ssh-backend

backend ssh-backend
    mode tcp
    option tcplog
    server ssh-server 127.0.0.1:2222
END

wget -O /usr/bin/badvpn "${GITHUB_REPO}/badvpn" >/dev/null 2>&1
chmod 777 /usr/bin/badvpn
}

function install_dropbear() {
print_pasang "Installasi dropbear"

cat > /etc/default/dropbear <<-END
# disabled because OpenSSH is installed
# change to NO_START=0 to enable Dropbear
NO_START=0
# the TCP port that Dropbear listens on
DROPBEAR_PORT=111
DROPBEAR_PORT=143

# any additional arguments for Dropbear
DROPBEAR_EXTRA_ARGS="-p 109 -p 69 "

# specify an optional banner file containing a message to be
# sent to clients before they connect, such as "/etc/issue.net"
DROPBEAR_BANNER="/etc/issue.net"

# RSA hostkey file (default: /etc/dropbear/dropbear_rsa_host_key)
#DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"

# DSS hostkey file (default: /etc/dropbear/dropbear_dss_host_key)
#DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"

# ECDSA hostkey file (default: /etc/dropbear/dropbear_ecdsa_host_key)
#DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"

# Receive window size - this is a tradeoff between memory and
# network performance
DROPBEAR_RECEIVE_WINDOW=65536
END

sleep 1
echo -e "[ ${green}INFO$NC ] Settings banner"
cat > /etc/issue.net <<-END
<p style="text-align:center"> <font color='#FF0059'>▬</font><font color='#F1006F'>▬</font><font color='#E30085'>▬</font><font color='#D6009B'>▬</font><font color='#C800B1'>▬</font><font color='#BB00C7'>ஜ</font><font color='#AD00DD'>۩</font><font color='#9F00F3'>۞</font><font color='#9F00F3'>۩</font><font color='#AD00DD'>ஜ</font><font color='#BB00C7'>▬</font><font color='#C800B1'>▬</font><font color='#D6009B'>▬</font><font color='#E30085'>▬</font><font color='#F1006F'>▬</font><br> <font color="#F5FE00"><b> --- 卍 XDXL PROJECT 卐 --- </b></font><br> <font color='red'>! TERM OF SERVICE !</font><br> <font color='#20CDCC'><b> NO SPAM </font><font color='#10C7E5'>NO DDOS </b></font><br> <font color='red'><b><u>NO HACKING AND CARDING</font><br> <font color="#E51369">NO TORRENT!!</u></font><br> <font color="#483D8B"><b>Order Premium : <br>wa.me/6285935195701 / <br>t.me/xdxl_store</font><font color="#483D8B"><b></font><br> <font color='#FF0059'>▬</font><font color='#F1006F'>▬</font><font color='#E30085'>▬</font><font color='#D6009B'>▬</font><font color='#C800B1'>▬</font><font color='#BB00C7'>ஜ</font><font color='#AD00DD'>۩</font><font color='#9F00F3'>۞</font><font color='#9F00F3'>۩</font><font color='#AD00DD'>ஜ</font><font color='#BB00C7'>▬</font><font color='#C800B1'>▬</font><font color='#D6009B'>▬</font><font color='#E30085'>▬</font><font color='#F1006F'>▬</font><br><a href="Group WA : https://chat.whatsapp.com/×××"><strong><span style="font-family:Trebuchet MS,Helvetica,sans-serif"> THANKS  FOR PREMIUM </span></strong></a><br>
END
chmod 777 /etc/issue.net
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear

/etc/init.d/ssh restart
/etc/init.d/dropbear restart

echo "0 0 * * * root xp" >> /etc/crontab
echo "0 3 * * * root clearlog && reboot" >> /etc/crontab

rm -f /etc/stunnel/stunnel.conf
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 222
connect = 127.0.0.1:22

[dropbear]
accept = 777
connect = 127.0.0.1:109

[ws-stunnel]
accept = 2096
connect = 700

[openvpn]
accept = 442
connect = 127.0.0.1:1194

END

# make a certificate
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart
/etc/init.d/stunnel4 status

apt install -y fail2ban
/etc/init.d/fail2ban restart
/etc/init.d/fail2ban status

# Instal DDOS Flate
if [ -d '/usr/local/ddos' ]; then
echo; echo; echo "Please un-install the previous version first"
#exit 0
else
mkdir /usr/local/ddos
fi
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'

iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

# remove unnecessary files
sleep 1
echo -e "[ ${green}INFO$NC ] Clearing trash"
apt autoclean -y >/dev/null 2>&1
if dpkg -s unscd >/dev/null 2>&1; then
apt -y remove --purge unscd >/dev/null 2>&1
fi
apt-get -y --purge remove samba* >/dev/null 2>&1
apt-get -y --purge remove apache2* >/dev/null 2>&1
apt-get -y --purge remove bind9* >/dev/null 2>&1
apt-get -y remove sendmail* >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
# finishing
cd
chown -R www-data:www-data /home/vps/public_html
sleep 1

history -c
echo "unset HISTFILE" >> /etc/profile
}

function udp_hc() {
print_pasang "Installasi Service Udp custom"
wget -q https://github.com/zhets/project/raw/main/ssh/udp-custom.sh
chmod 777 udp-custom.sh && ./udp-custom.sh
}

function download_xray() {
print_pasang "Installasi Service Xray"
date
timedatectl set-ntp true
echo -e "[ ${green}INFO$NC ] Enable chronyd"
systemctl enable chronyd
systemctl restart chronyd
sleep 1
echo -e "[ ${green}INFO$NC ] Enable chrony"
systemctl enable chrony
systemctl restart chrony
timedatectl set-timezone Asia/Jakarta
sleep 1
echo -e "[ ${green}INFO$NC ] Setting chrony tracking"
chronyc sourcestats -v
chronyc tracking -v
echo -e "[ ${green}INFO$NC ] Setting dll"
ntpdate pool.ntp.org
apt install pwgen netcat -y

echo -e "[ INFO ] Downloading & Installing xray core"
domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
chown www-data.www-data $domainSock_dir
# Make Folder XRay
mkdir -p /var/log/xray
mkdir -p /etc/xray
chown www-data.www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /var/log/xray/access2.log
touch /var/log/xray/error2.log

latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
# / / Installation Xray Core
xraycore_link="https://github.com/XTLS/Xray-core/releases/download/v$latest_version/xray-linux-64.zip"
# / / Ambil Xray Core Version Terbaru
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version >/dev/null 2>&1

# / / Make Main Directory
mkdir -p /usr/bin/xray
mkdir -p /etc/xray
mkdir -p /usr/local/etc/xray
# / / Unzip Xray Linux 64
cd `mktemp -d`
curl -sL "$xraycore_link" -o xray.zip
unzip -q xray.zip && rm -rf xray.zip
mv xray /usr/local/bin/xray
chmod 777 /usr/local/bin/xray
sleep 0.5

domain=$(cat /root/domain)

systemctl stop nginx
mkdir /root/.acme.sh
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc

# nginx renew ssl
echo -n '#!/bin/bash
/etc/init.d/nginx stop
"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" &> /root/renew_ssl.log
/etc/init.d/nginx start
/etc/init.d/nginx status
' > /usr/local/bin/ssl_renew.sh
chmod +x /usr/local/bin/ssl_renew.sh
if ! grep -q 'ssl_renew.sh' /var/spool/cron/crontabs/root;then (crontab -l;echo "15 03 */3 * * /usr/local/bin/ssl_renew.sh") | crontab;fi

cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/xdxl.pem

uuid=$(cat /proc/sys/kernel/random/uuid)
rm -rf /etc/systemd/system/xray.service.d
rm -rf /etc/systemd/system/xray@.service

cat <<EOF> /etc/systemd/system/xray.service
Description=Xray Service By PT.XD Project
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF
cat > /etc/systemd/system/runn.service <<EOF
[Unit]
Description=Mantap-Sayang
After=network.target

[Service]
Type=simple
ExecStartPre=-/usr/bin/mkdir -p /var/run/xray
ExecStart=/usr/bin/chown www-data:www-data /var/run/xray
Restart=on-abort

[Install]
WantedBy=multi-user.target
EOF

# Install Trojan Go
latest_version="$(curl -s "https://api.github.com/repos/p4gefau1t/trojan-go/releases" | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
trojango_link="https://github.com/p4gefau1t/trojan-go/releases/download/v${latest_version}/trojan-go-linux-amd64.zip"
mkdir -p "/usr/bin/trojan-go"
mkdir -p "/etc/trojan-go"
cd `mktemp -d`
curl -sL "${trojango_link}" -o trojan-go.zip
unzip -q trojan-go.zip && rm -rf trojan-go.zip
mv trojan-go /usr/local/bin/trojan-go
chmod 777 /usr/local/bin/trojan-go
mkdir /var/log/trojan-go/
touch /etc/trojan-go/akun.conf
touch /var/log/trojan-go/trojan-go.log

wget -O /etc/trojan-go/config.json ${GITHUB_REPO}/trojan.json
chmod 777 /etc/trojan-go/config.json

cat > /etc/systemd/system/trojan-go.service << END
[Unit]
Description=Trojan-Go Service Mod By PT.XD Project
Documentation=github.com/zhets
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/trojan-go -config /etc/trojan-go/config.json
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
END

# Trojan Go Uuid
cat > /etc/trojan-go/uuid.txt << END
$uuid
END

mv /root/domain /etc/xray/ 

}

function pasang_menu() {
wget ${GITHUB_REPO}/project.zip
unzip project.zip
chmod 777 project/*
mv project/* /usr/local/sbin
rm -rf /root/project
rm -rf project.zip
cd
cd /usr/local/bin
wget ${GITHUB_REPO}/ws.zip
unzip ws.zip
rm ws.zip
chmod 777 /usr/local/bin/ws-dropbear
chmod 777 /usr/local/bin/ws-stunnel
cd
cd /etc/systemd/system
wget ${GITHUB_REPO}/service.zip
unzip service.zip
rm service.zip
cd
clear
cat> /root/.profile << END
# ~/.profile: executed by Bourne-compatible login shells.

if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n || true
clear
menu
END
chmod 644 /root/.profile
}

function ins_backup() {
print_pasang "Installasi backup server"
apt install rclone -y > /dev/null 2>&1
printf "q\n" | rclone config
wget -O /root/.config/rclone/rclone.conf "${GITHUB_REPO}/rclone.conf"
git clone  https://github.com/magnific0/wondershaper.git
cd wondershaper
make install
cd
rm -rf wondershaper
echo > /home/limit
apt install msmtp-mta ca-certificates bsd-mailx -y
cat<<EOF>>/etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account default
host smtp.gmail.com
port 587
auth on
user hanskorbackup9@gmail.com
from hanskorbackup9@gmail.com
password wbgqpokjbkkjjiet
logfile ~/.msmtp.log
EOF
chown -R www-data:www-data /etc/msmtprc
cd
}

function restartser() {
print_pasang "Restart all service"
systemctl daemon-reload
sleep 1
echo -e "$yell[SERVICE]$NC Restart & Enable All service SSH & OVPN"
/etc/init.d/nginx restart >/dev/null 2>&1
/etc/init.d/openvpn restart >/dev/null 2>&1
/etc/init.d/ssh restart >/dev/null 2>&1
/etc/init.d/dropbear restart >/dev/null 2>&1
/etc/init.d/fail2ban restart >/dev/null 2>&1
/etc/init.d/stunnel4 restart >/dev/null 2>&1
/etc/init.d/vnstat restart >/dev/null 2>&1
/etc/init.d/squid restart >/dev/null 2>&1
systemctl disable badvpn1 
systemctl stop badvpn1 
systemctl enable badvpn1
systemctl start badvpn1 
systemctl disable badvpn2 
systemctl stop badvpn2 
systemctl enable badvpn2
systemctl start badvpn2 
systemctl disable badvpn3 
systemctl stop badvpn3 
systemctl enable badvpn3
systemctl start badvpn3 
systemctl enable noobzvpns
systemctl restart noobzvpns
echo -e "[ ${green}ok${NC} ] Enable & Restart All Service Websocket "
systemctl enable ws-dropbear
systemctl restart ws-dropbear
systemctl enable ws-stunnel
systemctl restart ws-stunnel
echo -e "[ ${green}ok${NC} ] Enable & Restart All Service Xray "
systemctl enable xray
systemctl restart xray
systemctl restart nginx
systemctl enable runn
systemctl restart runn
systemctl stop trojan-go
systemctl start trojan-go
systemctl enable trojan-go
systemctl restart trojan-go
systemctl enable haproxy
systemctl restart haproxy
systemctl enable client
systemctl restart client
systemctl enable server
systemctl restart server
cat > /home/re_otm <<-END
3
END

service cron restart >/dev/null 2>&1
service cron reload >/dev/null 2>&1
/etc/init.d/cron restart
systemctl restart cron
}

function install() {
xd_ganteng
buat_folder
pasang_domain
ins_vnstat
Swap_Gotop
password_ssh
sldns
udp_hc
ins_noobz
install_dropbear
download_xray
konfigurasi_paket
pasang_menu
ins_backup
restartser
}
checking_vps
install

rm /root/limit >/dev/null 2>&1
rm /root/setup.sh >/dev/null 2>&1
rm /root/setup.sh >/dev/null 2>&1
rm /root/ins-xray.sh >/dev/null 2>&1
rm /root/insshws.sh >/dev/null 2>&1
rm /root/ins-udp.sh >/dev/null 2>&1
rm /root/cf >/dev/null 2>&1
rm /root/.gh
rm -f /root/key.pem
rm -f /root/cert.pem
touch /root/.system 
secs_to_human() {
    echo "Installation time : $(( ${1} / 3600 )) hours $(( (${1} / 60) % 60 )) minute's $(( ${1} % 60 )) seconds"
}
start=$(date +%s)
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
secs_to_human "$(($(date +%s) - ${start}))"

clear
echo -e ""
echo -e "Installasi Berjalan Dengan Sukses"
echo -e "Silahkan ganti port login vps dari 22 menjadi 2222"
history -c
echo -e ""
read -p " Enter for rebooting vps";reboot
