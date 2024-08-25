#!/bin/bash

### These options are required to ensure the following:
### - err traps are inherited
### - piplined commands fail
### - we fail on unset variables
### see https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html for more details
set -eEuo pipefail

INTERNAL_ADDR=""
PUBLIC_ADDR=""
MTU=""
TUNNEL_MTU=""
CUSTOM_SSH_PORT=""
DEFAULT_GATEWAY=""
ENABLE_GN_CONNECTION=""
DNS_IP=""
SENSOR_PRIV_KEY=""
SENSOR_PUB_KEY=""
SENSOR_NET_INTERFACE=""

#############################################
#           CONSTANTS
#############################################

GREEN_CODE='\033[1;92m'
RESET_CODE='\033[0m'
RED_CODE='\033[1;91m'
YELLOW_CODE='\033[1;93m'

#  COLORS BELOW ARE USED FOR ASCII ART
#############################################
# ref: https://gist.github.com/WestleyK/dc71766b3ce28bb31be54b9ab7709082

WHITE='\033[1;97m'
CYAN='\033[1;96m'
PURPLE='\033[1;95m'
YELLOW='\033[1;93m'
BLUE='\033[1;94m'
PINK='\033[35;1m'
GREEN='\033[1;32m'


HEAD_RAND_COLORS=( $YELLOW $PURPLE $BLUE $PINK $GREEN )
# Randomly assign a color for banner
BANNER_SENSOR_VERSION=0.5
RAND=${HEAD_RAND_COLORS[ $RANDOM % ${#HEAD_RAND_COLORS[@]} ]}

#############################################

# Logging
LOG_PATH=/opt/greynoise/logs
LOG=$LOG_PATH/bootstrap.log

mkdir -p $LOG_PATH
touch $LOG

#------ HELPER FUNCTIONS ---------#

function log() {
	echo "[ $(date -u --iso-8601="ns") ] $1" >>$LOG 2>&1
}

function border() {
	log "INFO: $1"

	title="| $1 |"
	edge=$(echo "$title" | sed 's/./-/g')

	space
	echo "$edge"
	echo "$title"
	echo "$edge"
	space
}

function space() {
	echo ""
}

function green_check() {
	log "INFO: $1"

	echo -n -e $GREEN_CODE
	printf "\xE2\x9C\x94 $1"
	echo -e $RESET_CODE
}

function red_cross() {
	log "ERROR: $1"

	echo -n -e $RED_CODE
	printf "\xE2\x9D\x8C $1"
	echo -e $RESET_CODE

	return 1
}

function yellow_msg() {
	log "INFO: $1"

	echo -n -e $YELLOW_CODE
	echo -n "$1"
	echo -e $RESET_CODE
}

#----------------------------------#
#

function splash_image() {
    echo -n -e $CYAN ".;;. .,:'. .;;'...,;;'. ..,,;;;,,,,,,,,,;;;;;;,....';:;'. .;:,. .::. .,c,.\n"
    echo -n -e $CYAN ".:,. ':,. .;;. .';;'. .';;,,...................,;;;,....;:,. .;:,..'c;. .c;\n"
    echo -n -e $CYAN ":' .,:. .,:' .';,. .';;,....',,,,,,,,,,;;;;;;;,....,;:,. .;:;. .::. .::. .:\n"
    echo -n -e $CYAN ". .;;. .:;. .;;. .,:,. ..,;;,'..           ...,;;;'. .,:;. .;:' .,c,..,c' .\n"
    echo -n -e $CYAN " .;;. ':' .,:' .':,. .,;;'.   "$RAND"..............."$CYAN"   ..;:;. .,:,. .:;. .c;. ,c'\n"
    echo -n -e $CYAN ".;;. ':' .;;. .;;. .,:,.    "$RAND".','''''"$WHITE",,,,"$RAND"'''',,."$CYAN"    .,:;. .;:. .;:. .c;. ,c.\n"
    echo -n -e $CYAN ",:. .:' .;;. .:,. .:,.   "$RAND"..,'..'"$WHITE",;;;;;;;;;,"$RAND"'..,,'."$CYAN"   .,c,. ,c, .;c. .c;..;c\n"
    echo -n -e $CYAN ":. .:, .;:. .:, .,:'   "$RAND".','"$WHITE"..;:;'..     ..';:;.."$RAND"','.   "$CYAN".::. 'c, .;:. 'c' .c\n"
    echo -n -e $CYAN ";  ,:. ':. .:,  ,:.   "$RAND"',. "$WHITE".;c,.             .,c;"$RAND"...;'   "$CYAN".::. ,c' .c;. ;c. '\n"
    echo -n -e $CYAN ". .:' .:,  ;;. ':.   "$RAND".,' "$WHITE".:c.                 .cc."$RAND" ';.   "$CYAN".c; .;:. ,c. .c, .\n"
    echo -n -e $CYAN ". ,:. ':. .:' .:,    "$RAND".;;"$WHITE".:c.  .',,.     .,,'.  .cc'"$RAND"::.    "$CYAN",c. .c, .c; .::.\n"
    echo -n -e $CYAN " .;;. ;;. ,:. ':.   "$RAND".,ccl"$WHITE"d;  .ldkxo,  .;oxkdc.  ;'"$RAND"xoll;.   "$CYAN".c; .::. ;c. ,c.'\n"
    echo -n -e $CYAN " .;; .;;  ;;. ,:.   "$RAND".::;c"$WHITE"x;  ,odOkd:  .cdxOxl'  ,x"$RAND"l:cc'   "$CYAN".::. ;c. ,c. 'c.\n"
    echo -n -e $CYAN " .;, .;;  ;;. ,:.   "$RAND".:c:l"$WHITE"x,   ';::,.   .;::;.   ,x"$RAND"oclc.    "$CYAN"::. ;c. ,c. 'c'\n"
    echo -n -e $CYAN " .;; .;;. ,:. ':.     "$RAND".',"$WHITE"d;                     ,d"$RAND"l;'.    "$CYAN".:: .::. ;c. ,c.\n"
    echo -n -e $CYAN "  ,:. ,;. .,. ...       "$RAND"."$WHITE"l;                     ,l"$RAND".       "$CYAN".'. .;, .::. ;c.\n"
    echo -n -e $CYAN ". .'. ...               "$WHITE".l;                     ,l."$CYAN"                ..  ''\n"
    echo -n -e $WHITE "                        .l;                     ,l.\n"
    echo -n -e $WHITE "                        .l;                     ,l.\n"
    echo -n -e $WHITE "                        .c;..,.    .,;,.   .:o, ,l.\n"
    echo -n -e $WHITE "                       .oo::;::,';:;;::;',:c:..cx,\n"
    echo -n -e $WHITE "                        .::.   .;:,.   .':;.   .;c'\n"
    echo ""
    echo ""

    echo -n -e '\033[37;1m' "                        GREYNOISE - ""$RESET_CODE""$RAND""SENSORS VERSION $BANNER_SENSOR_VERSION\n"
    echo -n -e $RESET_CODE
}

function contains_element() {
    local e match="$1"
    shift
    for e; do [[ "$match" =~ "$e" ]] && return 0; done
    return 1
}

function inspect_operating_system() {
    source /etc/os-release
    UBUNTU_SUPPORTED_VERSIONS=("24.04" "23.04" "22.04" "20.04")
    DEBIAN_SUPPORTED_VERSION=("12" "12.1")

    border "Inspecting Operating system"
    if [[ $NAME =~ Ubuntu ]]; then
        green_check "Ubuntu is a supported Operating System"
        border "Inspecting if Installed version of Ubuntu is supported"
        if contains_element "$VERSION_ID" "${UBUNTU_SUPPORTED_VERSIONS[@]}"; then
            green_check "Ubuntu version: $VERSION_ID is supported by GreyNoise bootstrap"
            readonly OS_TYPE="Ubuntu"
        else
            red_cross "The Ubuntu version installed $VERSION_ID is currently not supported"
            return 1
        fi
    elif [[ $NAME =~ Debian ]]; then
        green_check "Debian is a supported Operating System"
        border "Inspecting if Installed version of Debian is supported"
        if contains_element "$VERSION_ID" "${DEBIAN_SUPPORTED_VERSION[@]}"; then
             green_check "Debian version: $VERSION_ID is supported by GreyNoise bootstrap"
             readonly OS_TYPE="Debian"
        else
            red_cross "The Debian version installed $VERSION_ID is currently not supported"
            return 1
        fi
    else
        red_cross "We currently are not supporting the installed Operating system $NAME"
        return 1
    fi
    green_check "Successfully verified Operating System"
}

function install_dependencies() {
	border "Installing Bootstrap dependencies"
	log "INFO: Starting apt update..."
	apt update >>$LOG 2>&1
	if [[ $OS_TYPE == "Ubuntu" ]]; then
	    if test -f /etc/needrestart/needrestart.conf; then
		    sed -i "s/#\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/g" /etc/needrestart/needrestart.conf
		else
	        mkdir -p /etc/needrestart
			echo "$nrconf{restart} = 'a';" > /etc/needrestart/needrestart.conf
		fi
    fi

	packages=(
		iproute2
		iptables
		iptables-persistent
		jq
		curl
		openssh-server
		wireguard-tools
	)
	for pkg in "${packages[@]}"; do
		log "INFO: Querying dpkg for $pkg..."
		if ! dpkg -l "$pkg" >>$LOG 2>&1; then
			yellow_msg "Installing package $pkg"
			if ! apt install -y "$pkg" >>$LOG 2>&1; then
				red_cross "Failed to install $pkg, please re-run script."
				return 1
			fi
		fi
	done
	green_check "Successfully installed all required dependencies"
}

function configure_packet_filter() {
	border "Configuring Packet filters"
	iptables -t mangle -F PREROUTING >>$LOG 2>&1
	if [[ "$ENABLE_GN_CONNECTION" == "true" ]]; then
		iptables -t mangle -A PREROUTING --source "${DNS_IP}" -j ACCEPT
		iptables -t mangle -A PREROUTING --source "api.greynoise.io" -j ACCEPT
	fi
	iptables -t mangle -A PREROUTING -p tcp --dport "${CUSTOM_SSH_PORT}" -j ACCEPT >>$LOG 2>&1
	iptables -t mangle -A PREROUTING --source "169.254.0.0/16" -j ACCEPT >>$LOG 2>&1
	iptables -t mangle -A PREROUTING --source "1-nlb-674c0284115aa12d.elb.us-east-1.amazonaws.com" -j ACCEPT >>$LOG 2>&1
	iptables -t mangle -A PREROUTING -i "${SENSOR_NET_INTERFACE}" --destination "${INTERNAL_ADDR}" -j MARK --set-mark 3 >>$LOG 2>&1
	iptables -t mangle -A PREROUTING -i "${SENSOR_NET_INTERFACE}" --destination "${INTERNAL_ADDR}" -j TTL --ttl-inc 2
	iptables -t mangle -A PREROUTING -i wg0 --source "${INTERNAL_ADDR}" -j MARK --set-mark 4 >>$LOG 2>&1

	mkdir -p /etc/iptables
	iptables-save >/etc/iptables/rules.v4
	ip6tables-save >/etc/iptables/rules.v6
	green_check "Successfully configured packet filters"
}

function configure_dns() {
	if [[ "$ENABLE_GN_CONNECTION" == "true" ]]; then
		border "Disabling systemd-resolved and configuring DNS"
		sudo systemctl disable systemd-resolved
		sudo systemctl stop systemd-resolved
		sudo sed -i -e "s/nameserver.*/nameserver $DNS_IP/" /etc/resolv.conf
		green_check "Successfully configured DNS"
	fi
}

function configure_wireguard() {
	border "Configuring WireGuard Tunnel"
	mkdir -p /etc/wireguard

	local addrs=[]
	IFS=',' read -r -a addrs <<< "$INTERNAL_ADDR"

	log "INFO: Creating /etc/wireguard/wg0.conf"
	cat <<EOF >/etc/wireguard/wg0.conf
[Interface]
PrivateKey = ${SENSOR_PRIV_KEY}
Address = 172.16.1.2/32
Table = off
MTU = ${TUNNEL_MTU}
$( for elem in "${addrs[@]}"
do
  echo "PostUp = ip route add ${elem} dev wg0 scope link src 172.16.1.2 table 3"
done
)
[Peer]
PublicKey = JdGteKXjaqCkvzV1w1BcHoXUGy8h4XozQ5OLbsBunDs=
Endpoint = 1-nlb-674c0284115aa12d.elb.us-east-1.amazonaws.com:45000
PersistentKeepalive = 25
AllowedIPs = 0.0.0.0/0,172.16.1.2/32
EOF

	sudo systemctl enable wg-quick@wg0 >>$LOG 2>&1
	sudo systemctl start wg-quick@wg0 >>$LOG 2>&1
	green_check "Successfully Configured WireGuard"
}

function configure_services() {
	border "Configuring GreyNoise systemd service"

	log "INFO: Creating /lib/systemd/system/greynoise.service"
	cat <<EOF >/lib/systemd/system/greynoise.service
[Unit]
Description=GreyNoise routing service
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=on-failure
RestartSec=5
User=root
ExecStartPre=/bin/sleep 4
ExecStart=/opt/greynoise/routing.sh

[Install]
WantedBy=multi-user.target
EOF

	log "INFO: Creating /lib/systemd/system/greynoise_retries.service"
	cat <<EOF >/lib/systemd/system/greynoise_retries.service
[Unit]
Description=GreyNoise retry service

[Service]
User=root
ExecStart=/opt/greynoise/retry.sh
EOF

	log "INFO: Creating /lib/systemd/system/greynoise_retries.timer"
	cat <<EOF >/lib/systemd/system/greynoise_retries.timer
[Unit]
Description="Runs retry script every two minutes"

[Timer]
OnBootSec=0min
OnCalendar=*:0/1
Unit=greynoise_retries.service

[Install]
WantedBy=multi-user.target
EOF

	log "INFO: Creating /opt/greynoise/routing.sh"
	cat <<EOF >/opt/greynoise/routing.sh
#!/bin/bash

ip link set ${SENSOR_NET_INTERFACE} mtu ${MTU}
ip rule add preference 200 lookup local
ip rule add preference 100 fwmark 4 table 4
ip rule add preference 101 fwmark 3 table 3
ip route add default via "${DEFAULT_GATEWAY}" table 4
ip rule del preference 0
echo "Routing configuration complete - see previous log lines for errors"
EOF

	log "INFO: Creating /opt/greynoise/retry.sh"
	cat <<EOF >/opt/greynoise/retry.sh
#!/bin/bash

TIMEOUT=120
TIME=\$(wg show all dump | grep 0.0.0.0/0 | awk 'BEGIN { FS = " " } ; { print \$6 }')
NOW=\$(date +%s)
LAST_SEEN=\$(expr \$((NOW)) - \$((TIME)))

if [[ \$LAST_SEEN -gt 120 ]]; then
    echo "now=\$NOW, last_seen=\$TIME: restarting connection"
    systemctl restart wg-quick@wg0
fi

EOF

	log "INFO: updating script permissions..."
	chmod +x /opt/greynoise/routing.sh >>$LOG 2>&1
	chmod +x /opt/greynoise/retry.sh >>$LOG 2>&1

	log "INFO: Enabling and starting greynoise services..."
	systemctl daemon-reload
	systemctl enable greynoise.service >>$LOG 2>&1
	systemctl start greynoise.service >>$LOG 2>&1
	systemctl enable greynoise_retries.timer >>$LOG 2>&1
	systemctl start greynoise_retries.timer >>$LOG 2>&1

	green_check "Successfully configured GreyNoise systemd Service"

}

function configure_sysctl_settings() {
	border "Configuring Kernel Parameters"
	settings=(
		"net.ipv4.conf.all.forwarding"
		"net.ipv4.conf.default.forwarding"
		"net.ipv4.conf.all.accept_local"
		"net.ipv4.conf.default.accept_local"
	)

	log "INFO: Creating /etc/sysctl.d/99-sysctl.conf"
	echo '' >/etc/sysctl.d/99-sysctl.conf

	for setting in "${settings[@]}"; do
		log "INFO: Enabling '$setting' in /etc/sysctl.d/99-sysctl.conf"
		echo "$setting=1" >>/etc/sysctl.d/99-sysctl.conf
	done

	log "INFO: Loading sysctl settings from /etc/sysctl.d/99-sysctl.conf"
	sysctl -p /etc/sysctl.d/99-sysctl.conf >>$LOG 2>&1
	green_check "Successfully configured Kernel parameters"
}

function configure_custom_ssh_port() {
	border "Configuring custom port ssh port"

	yellow_msg "Checking if SSH is socket-activated..."
	socket_activated=$(systemctl status ssh.socket | grep "Active: active (running)" || true)

	if [[ -z $socket_activated ]]; then
		yellow_msg "SSH is not socket-activated, configuring via sshd"
		sed -i "s/#Port 22/Port ${CUSTOM_SSH_PORT}/g" /etc/ssh/sshd_config
		systemctl restart sshd >>$LOG 2>&1
	else
		yellow_msg "SSH is socket-activated, configuring via ssh.socket"
		mkdir -p /etc/systemd/system/ssh.socket.d
		cat >/etc/systemd/system/ssh.socket.d/listen.conf <<EOF
[Socket]
ListenStream=${CUSTOM_SSH_PORT}
EOF
		systemctl daemon-reload
		systemctl restart ssh.socket
	fi

	green_check "Successfully configured new ssh port"
	yellow_msg "SSH port set to $CUSTOM_SSH_PORT"
}

function generate_wireguard_sensor_key() {
	border "Generating WG Keys"
	SENSOR_PRIV_KEY=$(wg genkey)
	SENSOR_PUB_KEY=$(echo "$SENSOR_PRIV_KEY" | wg pubkey)
	green_check "Successfully generated WG Keys"
}

function assign_dns_ip_addr() {
	border "Assigning DNS IP address"
	DNS_IP=$1
	green_check "DNS IP address set to $1"
}

function assign_internal_addr() {
	border "Configuring Internal IP Address"
	INTERNAL_ADDR=$1
	green_check "Internal IP address set to $1"
}

function assign_public_ip_addr() {
	border "Configuring Public IP address"
	PUBLIC_ADDR=$1
	green_check "Public IP address set to $1"
}

function assign_api_key() {
	border "Setting GreyNoise API key"
	GREYNOISE_API_KEY=$1
	green_check "Successfully set GreyNoise API key"
}

function assign_custom_ssh_port() {
	border "Assigning Custom SSH port"
	re='^[0-9]+$'
	if ! [[ $1 =~ $re ]]; then
		red_cross "Custom SSH port must be an integer"
		return 1
	fi
	CUSTOM_SSH_PORT=$1
	green_check "Successfully configured custom SSH port to $1"
}

function assign_interface_name() {
	border "Assigning Network interface"
	SENSOR_NET_INTERFACE=$1
	green_check "Interface name set to $1"
}

function assign_default_gateway() {
	border "Assigning Default Gateway"
	DEFAULT_GATEWAY=$1
	green_check "Default gateway set to $1"
}

function assign_mtu() {
	border "Assigning MTU"
	MTU=$1
	TUNNEL_MTU=$(( MTU - 80 ))
	green_check "MTU set to $1, Tunnel MTU set to $TUNNEL_MTU"
}

function ensure_dns_ip_addr_set() {
	border "Inspecting DNS IP Address"
	if [ -z "$DNS_IP" ]; then
		green_check "No DNS IP address set, defaulting to Google DNS (8.8.8.8)..."
		DNS_IP="8.8.8.8"
		green_check "DNS IP address set to $DNS_IP"
	else
		green_check "DNS IP address already set to $DNS_IP"
	fi
}

function ensure_iface_name_set() {
	border "Inspecting network interfaces"
	if [ -z "$SENSOR_NET_INTERFACE" ]; then
		yellow_msg "No interface set, finding interface..."
		SENSOR_NET_INTERFACE=$(ip route get ${DNS_IP} | grep -oP 'dev \K[^ ]+')
		RESULT=$?
		if [[ $RESULT -ne 0 ]]; then
			red_cross "Failed to set interface (status $RESULT): $SENSOR_NET_INTERFACE"
			return 1
		fi
		green_check "Interface set to $SENSOR_NET_INTERFACE"
	else
		yellow_msg "Interface already set to $SENSOR_NET_INTERFACE"
	fi
}

function ensure_internal_addr_set() {
	border "Inspecting internal address"
	if [ -z "$INTERNAL_ADDR" ]; then
		yellow_msg "No internal IP address set, finding IP address..."
		INTERNAL_ADDR=$(ip route get $DNS_IP | grep -oP 'src \K[^ ]+')/32
		RESULT=$?
		if [[ $RESULT -ne 0 ]]; then
			red_cross "Failed to set internal address (status $RESULT): $INTERNAL_ADDR"
			return 1
		fi
		green_check "Internal IP address set to $INTERNAL_ADDR"
	else
		green_check "Internal IP address already set to $INTERNAL_ADDR"
	fi
}

function ensure_mtu_set() {
	border "Inspecting MTU"
	if [ -z "$MTU" ]; then
		green_check "No MTU set, defaulting to 1580 and 1500"
		MTU=1580
		TUNNEL_MTU=1500
		green_check "MTU set to $MTU, Tunnel MTU set to $TUNNEL_MTU"
	else
		green_check "MTU already set to $MTU, and Tunnel MTU already set to $TUNNEL_MTU"
	fi
}

function ensure_public_ip_addr_set() {
	border "Inspecting Public IP Address"
	if [ -z "$PUBLIC_ADDR" ]; then
		green_check "No public IP address set, finding public IP address..."
		PUBLIC_ADDR=$(curl -H "key: $GREYNOISE_API_KEY" https://api.greynoise.io/ping | jq -r .address)/32
		green_check "Public IP address set to $PUBLIC_ADDR"
	else
		green_check "Public IP address already set to $PUBLIC_ADDR"
	fi
}

function ensure_default_gateway_set() {
	border "Inspecting Default Gateway setting"
	if [ -z "$DEFAULT_GATEWAY" ]; then
		yellow_msg "No default gateway set, finding gateway..."
		DEFAULT_GATEWAY=$(ip route get $DNS_IP | grep -oP 'via \K[^ ]+')
		RESULT=$?
		if [[ $RESULT -ne 0 ]]; then
			red_cross "Failed to set default gateway (status $RESULT): $DEFAULT_GATEWAY"
			return 1
		fi
		green_check "Default gateway set to $DEFAULT_GATEWAY"
	else
		green_check "Default gateway already set to $DEFAULT_GATEWAY"
	fi
}

function ensure_ssh_port_set() {
	border "Inspecting SSH port configuration"
	if [ -z "$CUSTOM_SSH_PORT" ]; then
		yellow_msg "No custom SSH port set, assigning random SSH port"
		CUSTOM_SSH_PORT=62551
	else
		green_check "Custom SSH port already set to $CUSTOM_SSH_PORT"
	fi
}

function check_api_key_set() {
	border "Checking GreyNoise API Key"
	if [ -z ${GREYNOISE_API_KEY+x} ]; then
		red_cross "No API key set - unable to continue. Please pass in the flag -k [API_KEY], or set the environment variable GREYNOISE_API_KEY=[API_KEY]"
		return 1
	fi
	green_check "API key set"
}

function register_sensor() {
	border "Registering as a GreyNoise Sensor"
	mkdir -p /opt/greynoise
	SERVER_RESPONSE=$(curl -H "key: $GREYNOISE_API_KEY" -L -w "\n\n%{http_code}\n" --request POST https://api.greynoise.io/v1/workspaces/dcbac25e-f1af-4d2d-8718-933ba025f20f/sensors \
		--header 'Content-Type: application/json' \
		--data-raw "{
        \"public_ips\": $(echo -n "$PUBLIC_ADDR" | jq -cRs 'split(",")'),
        \"public_key\": \"$SENSOR_PUB_KEY\",
        \"default_gateway\": \"$DEFAULT_GATEWAY\",
        \"access_port\": $CUSTOM_SSH_PORT
    }")
	RESULT=$?
	STATUS_CODE=$(echo -n "$SERVER_RESPONSE" | tail -n 1)
	SERVER_JSON=$(echo "$SERVER_RESPONSE" | sed '$d')

	if [[ $RESULT -eq 0 && $STATUS_CODE =~ '201' ]]; then
		SENSOR_ID=$(echo "$SERVER_JSON" | jq -r '.sensor_id')
		if [[ -z $SENSOR_ID ]]; then
			red_cross "Failed to register sensor - API returned '$SERVER_JSON'"
			return 1
		fi
		echo "$SENSOR_ID" >/opt/greynoise/sensor.id

		green_check "Sensor successfully created!"
		space
		yellow_msg "Sensor ID is $SENSOR_ID"
		yellow_msg "Sensor ID saved to /opt/greynoise/sensor.id"
	else
		red_cross "Failed to register sensor - API returned '$SERVER_JSON'"
		return 1
	fi
}

function print_final_output {
	border "Finished GreyNoise Sensor bootstrap!"

	yellow_msg ">>>>>> ATTENTION <<<<<<"
	yellow_msg ""
	yellow_msg "Please keep the following information for your records: "
	yellow_msg "    1. Your Sensor ID is $SENSOR_ID"
	yellow_msg "    2. Your Sensors's SSH port has been changed to $CUSTOM_SSH_PORT"
	yellow_msg ""
	yellow_msg "Your sensor should now be visible in the GreyNoise UI at:"
	yellow_msg "    https://viz.greynoise.io/sensors"
	yellow_msg ""
	yellow_msg "To complete setup, we must restart your sensor's networking."
	yellow_msg "This will terminate your ssh session. If you need to ssh back in"
	yellow_msg "for any reason, remember to use the SSH port listed above."
	yellow_msg ""
	yellow_msg "Congratulations on your new Sensor!"
}

function gracefully_terminate_ssh_sessions {
	space
	green_check "closing ssh session"
	pkill --signal HUP sshd
}

#-------------------------------------------------------------
# ARGUMENT DOCUMENTATION
#-------------------------------------------------------------
# -g,--gateway     Default gateway for host
# -i,--internal-ip Sensor IP address
# -k,--key         GreyNoise API Key
# -n,--interface   Interface name
# -p,--public-ip   Sensor Public IP address (only needed if address on interface is different from actual internet-accessible address)
# -s,--ssh-port    Custom SSH port
# -d,--dns         Custom DNS IP address (defaults to 8.8.8.8 for Google DNS).  This is only used for setup unless the -a flag is also set.
# -a,--enable-api  Configure the sensor to allow it to communicate with the GreyNoise API.
#-------------------------------------------------------------

splash_image

trap "echo There was an error running the bootstrap. Please check the logs at $LOG" ERR

border "Running GreyNoise Sensor bootstrap"
yellow_msg "Inspecting operating system"
PLATFORM=$(uname)
if [[ $PLATFORM != "Linux" ]]; then
	red_cross "ERROR: currently only Linux sensors are supported"
	exit 1
fi

yellow_msg "Inspecting kernel version"
KERNEL_VERSION=$(uname -r | grep -oE '^[0-9]+.[0-9]+')
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -f 1 -d .)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -f 2 -d .)

if [[ "$KERNEL_MAJOR" -lt 5 ]]; then
	red_cross "Kernel major version needs to be at least 5"
	exit 1
fi

if [[ "$KERNEL_MAJOR" -eq 5 ]]; then
	if [[ "$KERNEL_MINOR" -lt 4 ]]; then
		red_cross "Kernel version needs to be at least 5.4"
		exit 1
	fi
	if [[ "$KERNEL_MINOR" -lt 6 ]]; then
		yellow_msg "IMPORTANT: Kernel version is less than 5.6. Install may not work, dependent on distribution-specific kernel module handling."
	fi
fi

TEMP=$(getopt \
	-o n:g:i:p:s:k:d:m:a \
	--long interface:,gateway:,internal-ip:,public-ip:,ssh-port:,key:,dns:,mtu:,enable-api \
	-- "$@")
if [ $? != 0 ] ; then
	red_cross "Failed to parse arguments.  Terminating..."
	exit 1
fi
eval set -- "$TEMP"

while true; do
	case "$1" in
	-n | --interface)
		yellow_msg "interface manually set"
		assign_interface_name "$2"
		shift 2
		;;
	-g | --gateway)
		yellow_msg "gateway manually set"
		assign_default_gateway "$2"
		shift 2
		;;
	-i | --internal-ip)
		yellow_msg "Internal IP address manually set"
		assign_internal_addr "$2"
		shift 2
		;;
	-p | --public-ip)
		yellow_msg "Public IP address manually set"
		assign_public_ip_addr "$2"
		shift 2
		;;
	-s | --ssh-port)
		yellow_msg "custom SSH port manually set"
		assign_custom_ssh_port "$2"
		shift 2
		;;
	-k | --key)
		yellow_msg "API key manually set"
		assign_api_key "$2"
		shift 2
		;;
	-d | --dns)
		yellow_msg "DNS IP manually set"
		assign_dns_ip_addr "$2"
		shift 2
		;;
	-m | --mtu)
		yellow_msg "MTU manually set"
		assign_mtu "$2"
		shift 2
		;;
	-a | --enable-api)
		yellow_msg "Enabling connection to GreyNoise API"
		ENABLE_GN_CONNECTION="true"
		shift 1
		;;
	--)
		shift
		break
		;;
	*)
		red_cross "Unknown flag provided: $1"
		exit 1
		;;
	esac
done

### be absolute sure that nothing will run interactively
export DEBIAN_FRONTEND=noninteractive

function main() {
	inspect_operating_system
	install_dependencies
	configure_sysctl_settings
	generate_wireguard_sensor_key
	### fallback to default for args if needed
	ensure_dns_ip_addr_set
	ensure_iface_name_set
	ensure_internal_addr_set
	ensure_public_ip_addr_set
	ensure_default_gateway_set
	ensure_ssh_port_set
	ensure_mtu_set
	check_api_key_set
	### core setup
	configure_custom_ssh_port
	configure_wireguard
	configure_packet_filter
	configure_dns
	register_sensor

	# Configure services will restart networking, but after a 2 second delay
	# enforced by the systemd service. Everything that runs after this point
	# must complete within 2 seconds.
	configure_services

	print_final_output
	gracefully_terminate_ssh_sessions
}

#-----
# run process
#-----
main
