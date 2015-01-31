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

UTILITY_NAME = 'iptables'
UTILITY_LOCATION = '/usr/sbin/'
INTERNAL_ADDR = '192.168.0.14'
EXTERNAL_ADDR = '192.168.0.15'

INCOMING_INTERFACE=''
OUTGOING_INTERFACE=''


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
iptables -P FORWARD DROP
iptables -X

#Inbound/Outbound TCP packets on allowed ports.
for tcpPort in ${ALLOW_TCP[*]}
do
    iptables -A OUTPUT -p tcp --dport $tcpPort -j ACCEPT
    iptables -A INPUT -p tcp --sport $tcpPort -m state --state NEW,ESTABLISHED -j ACCEPT
done

#Inbound/Outbound UDP packets on allowed ports.
for udpPort in ${ALLOW_UDP[*]}
do
    iptables -A OUTPUT -p udp --dport $udpPort -j ACCEPT
    iptables -A INPUT -p udp --sport $udpPort -m state --state NEW,ESTABLISHED -j ACCEPT
done

#Inbound/Outbound ICMP packets based on type numbers.


#Drop all packets destined for the firewall host from the outside.
iptables -A INPUT -d $EXTERNAL_ADDR -j DROP

#Do not accept any packets with a source address from the outside matching your internal network.
iptables -A INPUT -s $INTERNAL_ADDR -j DROP

#You must ensure the you reject those connections that are coming the “wrong” way (i.e., inbound SYN packets to high ports).
iptables -A INPUT 

#Accept fragments.
iptables -A INPUT -f -j ACCEPT
iptables -A OUTPUT -f -j ACCEPT

#Drop all TCP packets with the SYN and FIN bit set.
iptables -A INPUT -p tcp --tcp-flags SYN, FIN -j DROP

#Do not allow Telnet packets at all.
iptables -A INPUT -p tcp --dport 23 -j DROP
iptables -A OUTPUT -p tcp --dport 23 -j DROP

iptables -A INPUT -p tcp --sport 23 -j DROP
iptables -A OUTPUT -p tcp --sport 23 -j DROP 

#Block all external traffic directed to ports 32768 – 32775, 137 – 139, TCP ports 111 and 515.
iptables -A INPUT -p tcp --dport 32768:32775 -j DROP
iptables -A INPUT -p udp --dport 32768:32775 -j DROP

iptables -A INPUT -p tcp --dport 137:139 -j DROP
iptables -A INPUT -p udp --dport 137:139 -j DROP

iptables -A INPUT -p tcp --dport 111 -j DROP
iptables -A INPUT -p udp --dport 111 -j DROP

iptables -A INPUT -p tcp --dport 515 -j DROP
iptables -A INPUT -p udp --dport 515 -j DROP

#For FTP and SSH services, set control connections to "Minimum Delay" and FTP data to "Maximum Throughput".
iptables -A PREROUTING -t mangle -p tcp --sport ssh -j TOS --set-tos Minimize-Delay  
iptables -A PREROUTING -t mangle -p tcp --sport ftp -j TOS --set-tos Minimize-Delay
iptables -A PREROUTING -t mangle -p tcp --sport ftp-data -j TOS --set-tos Maximize-Throughput




