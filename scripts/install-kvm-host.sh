#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright Dirk Hillbrecht 2022

# Transform a (freshly installed) Hetzner root server with Ubuntu 22.04
# into a KVM host with IPv6-first virtual machines.
# This script implements a number of steps outlined in the
# IPv6 first guide, see
#              https://ipv6-first-guide.hillbrecht.de

# This is a long script. I tried to split it into parts but you should be somehow familiar with (bash) shell programming if you want to work on it.

# *******************
# *** Online help ***
# *******************
# If the script is called with the parameter "--asciidoc", it emits a man page in Asciidoc syntax.
# An appropriate preprocessor can produce an actual man page out of it.

[ "x$1" = "x--asciidoc" ] && { cat <<EOA
= `basename $0`(1)

== NAME

`basename $0` - Transforms a Hetzner root server into a KVM physical host with IPv6-first approach for the virtual machines.

== SYNOPSIS

$(basename $0) [-b|--batch] [-l|--login loginname [-n|--name username]] [-tz|--timezone timezone] [--no-reboot]

== DESCRIPTION

$(basename $0) transforms a Hetzner root server with a freshly installed Ubuntu 22.04 into a KVM server for virtual machines.
Among others, it performs these steps:

* Enable IPv6 forwarding
* Create a network bridge device
* Ensure correct MAC address for outbound communication
* Install tayga, bind9, and radvd servers
* Install the KVM environment
* Create an additional user who can access the virtual machines daemon

The script follows the steps outlined in the https://ipv6-first-guide.hillbrecht.de/[IPv6 first guide].

Note that $(basename $0) splits the process in multiple stages.
After each stage, the server needs to be rebooted.
To continue at the correct stage with the correct parameters, $(basename $0) writes some information into a `/var/lib/install-kvm` directory.
For debugging or development purposes, you can suppress these automatic reboots with the `-nrb/--noreboot` option.

In case of problems in one step, $(basename $0) stops the process and waits for manual invention.
It can be reinvoked afterwards as often as needed as all process steps check if they have already been executed and do not run again.

$(basename $0) must be run as root.

== OPTIONS

*-b|--batch*:: The process is started without any confirmation dialog.
Use this if the script is started by some automated process.

*-l|--login*:: Login for the additional user.
If not given, no additional user is created.

*-n|--name*:: Name of the additional user, quote if contains spaces.
If not given, the name of the additional user is the same asthe login.

*-tz|--timezone|--time-zone*:: Time zone to reconfigure the server to.
If empty, the time zone is not reconfigured.

*-nrb|--no-reboot|--noreboot*:: Do not reboot after the different stages.
Reboot and subsequent call of $(basename $0) must be performed manually.

== AUTHOR

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/ .

(C) Dirk Hillbrecht 2022

EOA
exit 0 ;
}
[ "x$1" = "x-h" -o "x$1" = "x--help" ] && { man `basename $0` || $0 --asciidoc | less ; exit 0 ; }


# *******************************
# *** Basic library functions ***
# *******************************
# These are some basic library functions, not specific to the script itself
# but needed by some of its operations (see below)
# Note that some of these functions expect utility programs to be installed.
# This installation is performed early enough in the script process so that the utilities are actually available.

# returns the name of the network interface which has the public route
# param: "-4" for IPv4, "-6" for IPv6, none for default IP version
publicInterface() {
	local prot
	[ "$1" = "-4" ] || [ "$1" = "-6" ] && prot="$1"
	ip -j $prot route | jq '.[] | select(.dst=="default") | .dev' | sed 's/"//g'
}

# return local IP address of public interface
# param: "-4" for IPv4, "-6" for IPv6, none for all IP versions
myIP() {
	local prot
	[ "$1" = "-4" ] || [ "$1" = "-6" ] && prot="$1"
	local ifname=$(publicInterface $prot)
	[ -n "$ifname" ] && ip -j $prot a | jq '.[] | select(.ifname=="'"$ifname"'") | .addr_info[] | select(.scope=="global") | .local' | sed 's/"//g'
}

# return the MAC address of the network hardware of the public interface
# param: "-4" for IPv4, "-6" for IPv6, none for default IP version
myMAC() {
	local prot
	[ "$1" = "-4" ] || [ "$1" = "-6" ] && prot="$1"
	local ifname=$(publicInterface $prot)
	[ -n "$ifname" ] && ip -j $prot a | jq '.[] | select(.ifname=="'"$ifname"'") | .address' | sed 's/"//g'
}

# converts a MAC address to an IPv6 host part (EUI 64 bits)
macToHostPart() {
	[ -z "$1" ] && { echo "ERROR (macToHostPart): No parameter given." ; exit 1 ; }
	IFS=':'; set $1; unset IFS
	local f
	f=$(printf %x $((0x$1 ^ 2)))
	[ ${#f} = 1 ] && f="0$f"
	echo "$f$2:${3}ff:fe$4:$5$6" | sed -E 's/^0{1,3}//g;s/:0{1,3}/:/g'
}

# returns the (uncompressed) prefix of the given IPv6 address
# The given address might be compressed (= having a "::" part).
# The output is always uncompressed.
prefixOfIPv6() {
	[ -z "$1" ] && { echo "ERROR (netPartOfIPv6): No parameter given." ; exit 1 ; }
	local a=$(ipv6calc --addr_to_uncompressed "$1" 2>/dev/null)
	[ -z "$a" ] && { echo "ERROR (netPartOfIPv6): Could not uncompress IPv6 address $1." ; exit 1 ; }
	echo $a | cut -d":" -f1-4
}

# Create a random IPv6 host part which will not be a EUI64 address
createRandomHostPart() {
	local a=$(printf %x $(( (RANDOM % 255) * (RANDOM % 255) )))
	local b=$(printf %x $(( RANDOM % 255 )))
	local c=$(printf %x $(( RANDOM % 253 )))
	[ ${#c} = 1 ] && c="0$c"
	local d=$(printf %x $(( RANDOM % 253 )))
	local e=$(printf %x $(( RANDOM % 255 )))
	[ ${#e} = 1 ] && e="0$e"
	local f=$(printf %x $(( (RANDOM % 255) * (RANDOM % 255) )))
	echo "$a:$b$c:$d$e:$f"
}

# Set the time zone of the system using systemd mechanics
setTimezone() {
	local tz="$1"
	local oldtz="$(timedatectl show -p Timezone --value)"
	[ -z "$tz" ] && echo "No time zone given. Not changing time zone" && return
	[ "$tz" = "$oldtz" ] && echo "Not changing time zone as it is already set to $tz" && return
	timedatectl list-timezones | grep "$tz" >/dev/null 2>&1 || { echo "ERROR (setTimezone): Time zone $tz is unknown." ; exit 1 ; }
	timedatectl set-timezone "$tz" || { echo "ERROR (setTimezone): Could not set time zone to $tz" ; exit 1 ; }
	echo "Time zone set from $oldtz to $tz"
}

# Issues a reboot after which command given as $1 is executed
# Execution is performed via an "at now".
# To ensure that the command is not executed before the reboot,
# atd is stopped before putting $1 into its execution queue.
# If this function finds any problems with setting up the continuation,
# it stops the process. Better safe than sorry.
rebootAndContinue() {
	[ -z "$1" ] && { echo "You must give a continuation command as parameter." ; exit 1 ; }
	[ -x "$1" ] || { echo "Cannot find $1 for continuation after reboot. Not rebooting." ; exit 1 ; }
	[ "enabled" != "$(systemctl is-enabled atd 2>/dev/null)" ] && { echo "atd is not enabled. Cannot continue with reboot." ; exit 1 ; }
	systemctl stop atd
	[ "active" = "$(systemctl is-active atd 2>/dev/null)" ] && { echo "Could not stop atd. Cannot start reliable continuation after reboot." ; exit 1 ; }
	echo "$1" | at now 2>/dev/null
	echo "Reboot initiated. Will continue with $1"
	( sleep 5 ; reboot )&
	exit 0
}


# ************************************
# *** Actual script step functions ***
# ************************************
# The script performs a number of steps.
# Each step is coded in one function below.
# The functions are coding-wise mutually independent
# but need to be executed in a specific order.
# They are all called from the stageX() methods further below

# Checks that this is run as root on an Ubuntu 22.04 Hetzner server
checkServer() {
	[ "root" != "$(whoami)" ] && { echo "Must be run as root." ; exit 1 ; }
#	[ -n "$(systemctl is-enabled libvirtd)" ] && { echo "libvirtd is already installed on this system. Seems I am not needed any more." ; exit 0 ; }
	local instimg="/installimage.conf"
	[ -f "$instimg" ] || { echo "This is not a Hetzner server, \"$instimg\" does not exist." ; exit 1 ; }
	local lsbfile="/etc/lsb-release"
	[ -f "$lsbfile" ] || { echo "Cannot find $lsbfile. This should not happen. Aborting" ; exit 1 ; }
	local distrib=$(grep "^DISTRIB_ID" $lsbfile 2>/dev/null | cut -d"=" -f2)
	[ "Ubuntu" != "$distrib" ] && { echo "This is not Ubuntu but $distrib Linux. Cannot handle this." ; exit 1 ; }
	local release=$(grep "^DISTRIB_RELEASE" $lsbfile 2>/dev/null | cut -d"=" -f2)
	[ "22.04" != "$release" ] && { echo "This is Ubuntu $release while I expect Ubuntu 22.04. Cannot work on this one." ; exit 1 ; }
}

# basic steps for installing a host
basicAPTUpgrade() {
	echo "Basic apt-based system upgrade"
	apt update -y
	apt-get -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" dist-upgrade -y --allow-downgrades --allow-remove-essential --allow-change-held-packages
}

# install the tools essential for the installation process
installEssentialTools() {
	echo "Adding git repository to apt configuration"
	add-apt-repository -y ppa:git-core/ppa
	apt update -y

	echo "Installing essential addons using apt"
	apt install -y jq wget git ebtables ipv6calc cpu-checker

	local YQ="/usr/local/bin/yq"
	[ -x "$YQ" ] || {
		echo "Installing yq directly"
		wget -qO $YQ https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64
		chmod a+x $YQ
		[ -z "$(yq --version 2>/dev/null)" ] && { echo "Failed to install yq" ; exit 1 ; }
	}
}

# Checks that the preconditions for virtualisation exist on the machine
checkVirtOK() {
	local virtcount=$(grep -E -c '(vmx|svm)' /proc/cpuinfo)
	[ -z "$virtcount" -o "$virtcount" -lt 1 ] && { echo "ERROR (checkVirtOK): No \"vmx\" or \"svm\" in /proc/cpuinfo. This system does not support virtualisation." ; exit 2 ; }
	kvm-ok 2>/dev/null | grep "KVM acceleration can be used" >/dev/null 2>&1 || { echo "ERROR (checkVirtOK): Efficient virtualisation is disabled in BIOS. Enable it and try again." ; exit 1 ; }
	echo "Virtualisation can be used on this machine"
}

# activate IPv6 forwarding in /etc/sysctl.conf
activateIPv6Forwarding() {
	local SYSCTL="/etc/sysctl.conf"
	grep '^net\.ipv6\.conf\.all\.forwarding=1' $SYSCTL >/dev/null 2>&1 && echo "IPv6 forwarding is already enabled globally in $SYSCTL." && return
	sed -i 's/^# *net\.ipv6\.conf\.all\.forwarding/net.ipv6.conf.all.forwarding/g;s/^net\.ipv6\.conf\.all\.forwarding.*/net.ipv6.conf.all.forwarding=1/g' $SYSCTL
	grep 'net\.ipv6\.conf\.all\.forwarding' $SYSCTL >/dev/null 2>&1 || cat >> $SYSCTL <<EOFA

# Enable IPv6 forwarding as this is a bridging KVM host
net.ipv6.conf.all.forwarding=1
EOFA
	grep 'net\.ipv6\.conf\.all\.forwarding=1' $SYSCTL >/dev/null 2>&1 || { echo "ERROR (activateIPv6Forwarding): Did not find IPv6 forwarding in $SYSCTL even though it should be there." ; exit 1 ; }
	echo "Activated IPv6 forwarding globally in $SYSCTL."
}

# Creates an entry in /etc/fstab which moves /tmp into a 2G ramdisk
tmpInRamDisk() {
	local FSTAB="/etc/fstab"
	grep -E "[[:alnum:]]+[[:blank:]]/tmp[[:blank:]]" $FSTAB >/dev/null 2>&1 && echo "There is already an entry for /tmp in $FSTAB. Not touching it." && return
	cat >> $FSTAB <<EOFFS

# Putting /tmp into ramdisk
none /tmp tmpfs size=2g 0 0
EOFFS
	grep -E "[[:alnum:]]+[[:blank:]]/tmp[[:blank:]]" $FSTAB >/dev/null 2>&1 || { echo "ERROR (tmpInRamDisk): Tried to add /tmp entry in $FSTAB but failed." ; exit 1 ; }
	mv /tmp /oldtmp && mkdir /tmp && mount /tmp && rm -rf /oldtmp
	echo "Moved /tmp into ramdisk and activated it."
}

# Adds the bridge device br0 to the Netplan configuration
# This should be done via YAML config editing.
# Currently, it's a bit hacky but as the config file itself is
# generated by an automated process (and therefore syntactically very predictable)
# it's ok...
createNetplanBridge() {
	local CFG="/etc/netplan/01-netcfg.yaml"
	[ -r "$CFG" ] || { echo "Cannot access Netplan configuration file $CFG." ; exit 1 ; }
	# If br0 already exists, do nothing
	grep "^    br0:$" $CFG >/dev/null 2>&1 && echo "br0 is already defined in $CFG. Not touching this." && return
	pubIF=$(publicInterface)
	mac=$(myMAC)
	[ -z "$pubIF" -o -z "$mac" ] && { echo "Could not determine public interface ($pubIF) or MAC address ($mac) but need both. Aborting." ; exit 1 ; }
	# Check that the detected public interface has an entry in the config
	grep "^    ${pubIF}:$" $CFG >/dev/null 2>&1 || { echo "Did not find definition for interface $pubIF in Netplan configuration $CFG. Aborting" ; exit 1 ; }
	# Use sed to add some lines after the public interface definition
	# This cleverly moves all definitions from the interface to the bridge
	# It's really in the twilight zone between cleverness and hackyness.
	sed -i "/^    ${pubIF}:/ a\      dhcp4: false\n      dhcp6: false\n  bridges:\n    br0:\n      accept-ra: false\n      macaddress: ${mac}\n      interfaces:\n        - ${pubIF}" $CFG
	grep "^    br0:$" $CFG >/dev/null 2>&1 || { echo "Could not add br0 defintion to $CFG. That is bad. Aborting." ; exit 1 ; }
	echo "Added br0 to Netplan configuration in $CFG"
}

# Adds the ebtables rule to /etc/rc.local
ebtablesToRcLocal() {
	local F="/etc/rc.local"
	[ -f "$F" ] || {
		echo "Creating $F as it does not exist"
		cat >$F <<EOFRCL
#!/bin/bash

exit 0
EOFRCL
	}
	grep "ebtables" $F >/dev/null 2>&1 && echo "There is already an ebtables line in $F. Not touching this." && return
	[ -x "$F" ] || {
		echo "Making $F executable"
		chmod +x $F
	}
	grep "exit 0" $F >/dev/null 2>&1 || {
		echo "Adding an \"exit 0\" line to $F"
		echo "exit 0" >> $F
	}
	mac=$(myMAC)
	[ -z "$mac" ] && { echo "ERROR (ebtablesToRcLocal): Could not determine MAC address. Aborting." ; exit 1 ; }
	sed -i "/exit 0/i# force source MAC address of all packets to the official address of the physical server\nebtables -t nat -A POSTROUTING -j snat --to-src $mac\n" $F
	grep "ebtables" $F >/dev/null 2>&1 || { echo "ERROR (ebtablesToRcLocal): Tried to add ebtables line but did not find it. Aborting." ; exit 1 ; }
	echo "Added ebtables snat line to MAC address $mac into $F"
}

# Install the Tayga NAT64 daemon
installTayga() {
	local F="/etc/tayga.conf"
	[ -f "$F" ] && echo "Not installing Tayga as $F already exists" && return
	local addr=$(myIP -6)
	[ -z "$addr" ] && { echo "ERROR (installTayga): Could not determine IPv6 address" ; exit 1 ; }
	local prefixpart=$(prefixOfIPv6 $addr)
	local hostpart=$(createRandomHostPart)
	local taygaIPv6Address=$(ipv6calc --addr_to_compressed "${prefixpart}:${hostpart}" 2>/dev/null)
	[ -z "$taygaIPv6Address" ] && { echo "ERROR (installTayga): Could not create IPv6 address out of prefix $prefixpart and host $hostpart" ; exit 1 ; }
	echo "Installing tayga"
	apt -y install tayga
	cat >$F <<EOFTY
# NAT64 Tayga configuration for KVM host with IPv6-only guests
# Generated by install-kvm-host

# (A) Basic setup
# Device name, this is the default
tun-device nat64
# Data dir for stateful NAT information
data-dir /var/spool/tayga

# (B) IPv6 setup
# The "well-known" prefix for NAT64
prefix 64:ff9b::/96
# IPv6 address, from the official ::/64 network
ipv6-addr $taygaIPv6Address

# (C) IPv4 setup
# Pool of dynamic addresses
dynamic-pool 192.168.255.0/24
# IPv4 address, not to be used otherwise in the network
ipv4-addr 192.168.255.1
EOFTY
	systemctl enable tayga 2>/dev/null
	[ "enabled" != "$(systemctl is-enabled tayga 2>/dev/null)" ] && { echo "ERROR (installTayga): Failed to enable Tayga service" ; exit 1 ; }
	echo "Tayga installed successfully"
}

# Install the Bind DNS resolver for DNS64 service
installBind() {
	local F="/etc/bind/named.conf.options"
	[ -f "$F" ] && echo "Not installing bind as $F exists." && return
	local P="/etc/netplan/01-netcfg.yaml"
	[ -f "$P" ] || { echo "ERROR (installBind): Could not find netplan configuration file $P. Aborting" ; exit 1 ; }
	local rawforwarders="$(cat "$P" | yq -o y '.[] | .bridges.br0.nameservers.addresses')"
	[ -z "$rawforwarders" -o "null" = "$rawforwarders" ] && { echo "Could not read forwarder DNS servers from $P. Aborting." ; exit 1 ; }
	local forwarders="$(echo "$rawforwarders" | cut -c3- | sed "s/^/    /g;s/$/;/g")"
	local ip=$(myIP -6)
	local rawprefix=$(prefixOfIPv6 $(myIP -6))
	[ -z "$rawprefix" ] && { echo "ERROR (installBind): Could not obtain IPv6 prefix. Aborting." ; exit 1 ; }
	local prefix=$(ipv6calc --addr_to_compressed "${rawprefix}:0:0:0:0" 2>/dev/null)
	[ -z "$prefix" ] && { echo "ERROR (installBind): Could not create full IPv6 network address from $rawprefix. Aborting." ; exit 1 ; }
	apt -y install bind9
	cat >$F <<EOFBIND
# Configuration for bind acting as local DNS64 resolver
# Generated by install-kvm-host

options {
  directory "/var/cache/bind";

  # Forwarders taken from $P
  forwarders {
$forwarders
  };

  # Some standard settings
  dnssec-validation auto;
  auth-nxdomain no;    # conform to RFC1035

  # Listen only on IPv6 and on this network
  listen-on {};
  listen-on-v6 {
    ${prefix}/64;
  };
  allow-query { localnets; };

  # Actually work as DNS64 resolver
  dns64 64:ff9b::/96 {
    clients { any; };
  };
};
EOFBIND
	systemctl enable bind9 2>/dev/null
	local realservice="$(systemctl show -p Id --value bind9)"
	[ "enabled" != "$(systemctl is-enabled "$realservice" 2>/dev/null)" ] && { echo "ERROR (installBind): Failed to enable Bind service (which is real service $realservice)." ; exit 1 ; }
	echo "Bind as DNS64 resolver installed and configured"
}

# Install radvd for virtual machine network autoconfiguration
installRadvd() {
	local F="/etc/radvd.conf"
	[ -f "$F" ] && echo "Not installing radvd as $F already exists." && return
	local ip=$(myIP -6)
	local rawprefix=$(prefixOfIPv6 "$ip")
	[ -z "$rawprefix" ] && { echo "ERROR (installRadvd): Could not obtain IPv6 prefix. Aborting." ; exit 1 ; }
	local prefix=$(ipv6calc --addr_to_compressed "${rawprefix}:0:0:0:0" 2>/dev/null)
	[ -z "$prefix" ] && { echo "ERROR (installRadvd): Could not create full IPv6 network address from $rawprefix. Aborting." ; exit 1 ; }
	apt -y install radvd radvdump
	cat >$F <<EOFRVD
interface br0 {
  AdvSendAdvert on;
  AdvManagedFlag off;
  AdvOtherConfigFlag off;
  AdvDefaultPreference high;
  prefix $prefix/64 {
    AdvOnLink on;
    AdvAutonomous on;
    AdvRouterAddr on;
    AdvValidLifetime infinity;
  };
  RDNSS $ip {};
  route 64:ff9b::/96 {
    AdvRouteLifetime infinity;
  };
};
EOFRVD
	echo "Radvd installed and configured"
}

# Install the KVM packages
installKVM() {
	echo "Installing KVM packages"
	apt install -y \
		bridge-utils \
		libguestfs-tools \
		libosinfo-bin \
		libvirt-clients \
		libvirt-daemon-system \
		libvirt-daemon virtinst \
		qemu \
		qemu-system-x86 || { echo "ERROR (installKVM): Something went wrong with installing the KVM packages" ; exit 1 ; }
	echo "KVM packages installed"
}

# Load the vhost_net module into the kernel and persist it
installVHostModule() {
	modprobe vhost_net
	local F="/etc/modules"
	grep "^vhost_net$" $F >/dev/null 2>&1 || {
		echo "vhost_net" >> $F
		echo "Added vhost_net to /etc/modules and loaded it"
	}
}

# Add an additional user to the system and copy root's authkeys
addKVMUser() {
	local login="$1"
	[ -z "$login" ] && echo "No login name given, not creating an additional user" && return
	[ -d "/home/$login" ] && echo "User $login does already exist." && return
	local name="$2"
	[ -z "$name" ] && name="$login"
	adduser --disabled-password --gecos "$name" $login || { echo "ERROR (addKVMUser): Could not create user" ; exit 1 ; }
	usermod -a -G libvirt "$login"
	sudo -u $login chmod 755 /home/$login
	echo "User $login ($name) added."
	local srcauth="/root/.ssh/authorized_keys"
	[ -f "$srcauth" ] && {
		local destauth="/home/$login/.ssh/authorized_keys"
		sudo -u $login mkdir "$(dirname "$destauth")"
		sudo -u $login chmod 700 "$(dirname "$destauth")"
		sudo -u $login touch "$destauth"
		sudo -u $login chmod 600 "$destauth"
		cat "$srcauth" >> "$destauth"
		echo "Copied root's ssh authkeys to $login"
	}
}

# High level reboot continuation method
continueWithStageAfterReboot() {
	command="$1"
	stagefile="$2"
	stage="$3"
	[ -z "$command" -o -z "$stagefile" -o -z "$stage" ] && { echo "ERROR (continueWithStageAfterReboot): need command ($command), stagefile ($stagefile) and stage ($stage) but did not get all three." ; exit 1 ; }
	echo "$stage" > $stagefile
	echo "Prepared stage $stage in file $stagefile. Now issuing reboot"
	rebootAndContinue "$command"
}


# *******************************
# *** Basic environment setup ***
# *******************************

# Prevent apt from any questions and suspend restart checks (the script restarts anyway).
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_SUSPEND=1

myself=$(readlink -f -- "$0")
mydir=$(dirname -- "$myself")

libdir=/var/lib/install-kvm
[ -d "$libdir" ] || mkdir -p "$libdir" || { echo "Cannot create libdir $libdir" | tee -a $logfile ; exit 1 ; }
[ -x "$libdir" ] || { echo "Access problem with libdir $libdir" | tee -a $logfile ; exit 1 ; }
stagefile=$libdir/stage
conffile=$libdir/config
logfile=/var/log/install-kvm.log

# Load the current stage to execute
[ -f "$stagefile" ] && currentstage=$(cat "$stagefile") || currentstage=1

# ****************************************
# *** Stage-specific environment setup ***
# ****************************************
# In stage 1, the parameters are read from the command line
# In all later stages, the parameters are read from the config file
# where they have been written in stage 1.

if [ "$currentstage" = "1" ]
then
	while [ -n "$1" ] ; do
		case "$1" in
		-l|--login) shift ; [ -z "$1" ] && { $0 -h ; exit 1 ; } ; export login="$1" ;;
		-n|--name) shift ; [ -z "$1" ] && { $0 -h ; exit 1 ; } ; export name="$1" ;;
		-tz|--timezone|--time-zone) shift ; [ -z "$1" ] && { $0 -h ; exit 1 ; } ; export tz="$1" ;;
		--no-reboot|--noreboot|-nrb) noreboot="true" ;;
		--batch|-b) batch="true" ;;
		*) ;;
		esac
		shift
	done
	# Special test: Is the given time zone valid?
	if [ -n "$tz" ]
	then
		timedatectl list-timezones | grep "$tz" >/dev/null 2>&1 || { echo "ERROR: Time zone $tz is unknown." ; exit 1 ; }
	fi
	# You must not give both "batch" and "no reboot" flag
	[ "$batch" = "true" -a "$noreboot" = "true" ] && { echo "ERROR: \"batch\" and \"no reboot\" flag are mutually exclusive." ; exit 1 ; }
	rm -f $conffile && touch $conffile && chmod +x $conffile
	[ -n "$login" ] && echo "export login=\"$login\"" >> $conffile
	[ -n "$name" ] && echo "export name=\"$name\"" >> $conffile
	[ -n "$tz" ] && echo "export tz=\"$tz\"" >> $conffile
	[ -n "$noreboot" ] && echo "export noreboot=\"$noreboot\"" >> $conffile
	echo "Ok, I will install the KVM environment"
	[ -n "$login" ] && echo "Additional user is $login, name is $name" || echo "No additional user will be created."
	[ -n "$tz" ] && echo "Time zone will be set to $tz" || echo "Time zone will not be changed from $(timedatectl show -p Timezone --value)"
	echo "Process is logged in $logfile"
	[ "$noreboot" = "true" ] && echo "I will NOT reboot automatically between the stages." || echo "I WILL REBOOT AUTOMATICALLY AFTER EACH STAGE!"
	if [ "$batch" = "true" ]
	then
		echo "Batch mode, starting the operation"
	else
		echo "Press Return to start or Ctrl-C to abort."
		read fff
	fi
else
	[ -f "$conffile" ] || { echo "ERROR: Expected conf file $conffile but cannot find it." | tee -a $logfile ; exit 1 ; }
	. $conffile
fi

# ***************************
# *** Workflow management ***
# ***************************
# The script operates in multiple stages.
# After each stage, the server is rebooted so that the configuration changes
# or installations are applied in a defined way.
# The whole workflow is split into one function per stage
# which calls the actual operation methods in the script
# needed in this stage in the right order

# Stage 1 performs some checks on preconditions and the basic setup
stage1() {
	checkServer
	basicAPTUpgrade
	setTimezone "$tz"
	installEssentialTools
	checkVirtOK
	activateIPv6Forwarding
	createNetplanBridge
	ebtablesToRcLocal
	tmpInRamDisk
}

# Stage 2 installs the helper programs for the KVM host
stage2() {
	installTayga
	installBind
	installRadvd
}

# Stage 3 installs the actual KVM environment with libvirtd
# and performs final steps
stage3() {
	installKVM
	installVHostModule
	addKVMUser "$login" "$name"
}

# execute one of the stages defined above according to the given parameter.
# This function also performs the final reboot after each stage
# or emits the appropriate message if automatic reboot has been
# disabled (--noreboot parameter).
performStage() {
	local stage="$1"
	[ -z "$stage" ] && { echo "ERROR (performStage): No stage given" ; exit 1 ; }
	case "$stage" in
		1|2|3) stage$stage ;;
		*) echo "ERROR (performStage): Stage $stage is unknown" ; exit 1 ;;
	esac
	if [ "$stage" -lt 3 ]
	then
		local newstage=$(( stage + 1 ))
		if [ "$noreboot" = "true" ]
		then
			echo "$newstage" > $stagefile
			echo "Stage $stage finished."
			echo "Reboot or perform other steps manually."
			echo "Then, call"
			echo "$myself"
			echo "again to continue with stage $newstage."
			echo "Note that parameters will not be evaluated in this subsequent call."
		else
			echo "Stage $stage finished."
			echo "Continuing with stage $newstage after a reboot"
			continueWithStageAfterReboot "$myself" "$stagefile" "$newstage"
		fi
	else
		rm -f "$stagefile" "$conffile"
		echo "KVM installation finished successfully."
		if [ "$noreboot" = "true" ]
		then
			echo "You should perform a final reboot."
		else
			echo "Performing final reboot..."
			( sleep 5 ; reboot )&
		fi
	fi
}

# ********************
# *** Main program ***
# ********************
# The main program simply calls performStage() with the current stage
# and routes all output into the log file.
# This is crucial as the connection to the terminal gets lost during
# the reboots and it must be possible to see what the script has actually
# done and if there were any errors.

performStage "$currentstage" | tee -a $logfile

# Note: If you want to test one step, you can just call the respective
# method here instead of performStage.
# You might have to disable some checks here and there to actually
# make the functions actually do anything...

# Example:
#setTimezone "$tz"

# end of file
