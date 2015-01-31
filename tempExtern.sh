# *************************************************************************************
# GEOFF DABU - A00817395, CHRIS HUNTER -
# COMP 8006 ASSIGNMENT 2 - FIREWALL USING IPTABLES
#
# THIS SCRIPT ENABLES A FIREWALL WHICH ABIDES TO THE FOLLOWING CONSTRAINTS:
#
# *************************************************************************************

# *************************
# USER CONFIGURABLE SECTION
# *************************

#UTILITY_NAME = 'iptables'
#UTILITY_LOCATION = '/usr/sbin/'
INTERNAL_ADDR='192.168.10.2'
SUBNET_ADDR='192.168.10.0/24'

PRIVATE_INTERFACE='p3p1'
PUBLIC_INTERFACE='em1'


ALLOW_TCP=(53 67 68 80 443)
ALLOW_UDP=(53)
#ALLOW_ICMP=()


# *************************
# IMPLEMENTATION SECTION
# *************************


# ******************************************************
# RESET CHAINS
# ******************************************************
iptables -F
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD ACCEPT
iptables -X

#-------------------------------------------------------------------------------------

iptables -t nat -A POSTROUTING -s $SUBNET_ADDR -o em1 -j SNAT --to-source 192.168.0.15

#Direct all incoming port 80 packets to 192.168.10.2
iptables -t nat -A PREROUTING -i em1 -p tcp --sport 1024:65535 -d em1 --dport 80 -j DNAT --to-destination 192.168.10.2

#For FTP and SSH services, set control connections to "Minimum Delay" and FTP data to "Maximum Throughput".
iptables -A PREROUTING -t mangle -p tcp --sport ssh -j TOS --set-tos Minimize-Delay
iptables -A PREROUTING -t mangle -p tcp --sport ftp -j TOS --set-tos Minimize-Delay
iptables -A PREROUTING -t mangle -p tcp --sport ftp-data -j TOS --set-tos Maximize-Throughput

#forward packets from public NIC to private network
iptables -t nat -A FORWARD -i em1 -o p3p1 -m state --state NEW, ESTABLISHED -j ACCEPT
#forward packets from private network to publci NIC
iptables -t nat -A FORWARD -i p3p1 -o em1 -j ACCEPT

#Block all external traffic directed to ports 32768 – 32775, 137 – 139, TCP ports 111 and 515.
iptables -A FORWARD -p tcp -m multiport --dport 32768:32775,137:139,111,115 -j DROP

#Do not allow Telnet packets at all.
iptables -A FORWARD -p tcp --dport 23 -j DROP
iptables -A FORWARD -p tcp --sport 23 -j DROP

#Drop all TCP packets with the SYN and FIN bit set.
iptables -A FORWARD -p tcp --tcp-flags SYN, FIN -j DROP

#Accept fragments.
iptables -A FORWARD -f -j ACCEPT


iptables -A FORWARD -s 192.168.10.0/24 -j DROP



#-----------------------------------------------------------------------------------------------------

#iptables -t nat -A PREROUTING -i $PUBLIC_INTERFACE -p tcp --dport 80 -j DNAT --to $INTERNAL_ADDR
#iptables -A FORWARD -i $PUBLIC_INTERFACE -o $PRIVATE_INTERFACE -p tcp --dport 80 -m state --state NEW -j ACCEPT

#iptables -A FORWARD -i $PRIVATE_INTERFACE -o $PUBLIC_INTERFACE -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
#iptables -A FORWARD -i $PUBLIC_INTERFACE -o $PRIVATE_INTERFACE -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT

#---------------------------------------------------------------------------------------------------

#iptables -t nat -A PREROUTING -i $PUBLIC_INTERFACE -j DNAT --to $INTERNAL_ADDR

#iptables -t nat -A POSTROUTING -o $PRIVATE_INTERFACE -j MASQUERADE

#iptables -A FORWARD -i $PUBLIC_INTERFACE -o $PRIVATE_INTERFACE -j ACCEPT
#iptables -A FORWARD -i $PRIVATE_INTERFACE -o $PUBLIC_INTERFACE -j ACCEPT






















