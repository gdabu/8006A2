# ********************************************************************************************************************************
# 					GEOFF DABU - A00817395, CHRIS HUNTER - A00833669
# 					COMP 8006 ASSIGNMENT 2 - FIREWALL USING IPTABLES
#
#
# THIS SCRIPT ENABLES A FIREWALL WHICH ABIDES TO THE FOLLOWING CONSTRAINTS:
	#Inbound/Outbound TCP packets on allowed ports.
	#Inbound/Outbound UDP packets on allowed ports.
	#Inbound/Outbound ICMP packets based on type numbers.
	#All packets that fall through to the default rule will be dropped.
	#Drop all packets destined for the firewall host from the outside.
	#Do not accept any packets with a source address from the outside matching your internal network.
	#You must ensure the you reject those connections that are coming the “wrong” way(i.e., inbound SYN packets to high ports).
	#Accept fragments.
	#Accept all TCP packets that belong to an existing connection (on allowed ports).
	#Drop all TCP packets with the SYN and FIN bit set.
	#Do not allow Telnet packets at all.
	#Block all external traffic directed to ports 32768-32775, 137-139, TCP ports 111and 515.
	#For FTP and SSH services, set control connections to "Minimum Delay" and FTP data to "Maximum Throughput
#
# ********************************************************************************************************************************



# **************************************************
# 	   USER CONFIGURABLE SECTION
# **************************************************

#UTILITY_NAME = 'iptables'
#UTILITY_LOCATION = '/usr/sbin/'
INTERNAL_ADDR='192.168.10.2'
FIREWALL_ADDR='192.168.0.24'
SUBNET_ADDR='192.168.10.0/24'

PRIVATE_INTERFACE='p3p1'
PUBLIC_INTERFACE='em1'

ALLOW_TCP='22,53,67,68,80,443'
ALLOW_UDP='53,67,80,443'
ALLOW_ICMP='8'



# **************************************************
# 	IMPLEMENTATION SECTION - DO NOT TOUCH
# **************************************************



# ***************************
# 	RESET CHAINS
# ***************************
iptables -t nat -F
iptables -F
iptables -P INPUT DROP    # MUST CHANGE
iptables -P OUTPUT DROP   # MUST CHANGE
iptables -P FORWARD DROP
iptables -X


# ***************************
# 	USER CHAINS
# ***************************

iptables -N tcpIN
iptables -N tcpOUT

iptables -N udpIN
iptables -N udpOUT

iptables -N icmpIN
iptables -N icmpOUT


# ***************************
# 	POSTROUTING
# ***************************

#Mask all outgoing as FIRE WALL ADDRESS
iptables -t nat -A POSTROUTING -s $SUBNET_ADDR -o $PUBLIC_INTERFACE -j SNAT --to-source $FIREWALL_ADDR



# ***************************
# 	 PREROUTING
# ***************************

#Direct all incoming packets to 192.168.10.2
iptables -t nat -A PREROUTING -i $PUBLIC_INTERFACE -j DNAT --to-destination $INTERNAL_ADDR

#For FTP and SSH services, set control connections to "Minimum Delay" and FTP data to "Maximum Throughput".
iptables -A PREROUTING -t mangle -p tcp --sport ssh -j TOS --set-tos Minimize-Delay
iptables -A PREROUTING -t mangle -p tcp --sport ftp -j TOS --set-tos Minimize-Delay
iptables -A PREROUTING -t mangle -p tcp --sport ftp-data -j TOS --set-tos Maximize-Throughput



# ***************************
#    DROP SPECIFIC PACKETS
# ***************************


#Drop all incoming packets with source addr,from outside network, matching internal netowrk
iptables -A tcpIN -i $PUBLIC_INTERFACE -o $PRIVATE_INTERFACE -s $SUBNET_ADDR -j DROP

#Drop all incoming packets with SYN bit directed at a high port
iptables -A tcpIN -i $PUBLIC_INTERFACE -o $PRIVATE_INTERFACE -p tcp --syn ! --dport 0:1024 -j DROP

#Drop all TCP packets with the SYN and FIN bit set.
iptables -A tcpIN -i $PUBLIC_INTERFACE -o $PRIVATE_INTERFACE -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

#Do not allow Telnet packets at all.
iptables -A tcpIN -i $PUBLIC_INTERFACE -o $PRIVATE_INTERFACE -p tcp --dport 23 -j DROP
iptables -A tcpIN -i $PUBLIC_INTERFACE -o $PRIVATE_INTERFACE -p tcp --sport 23 -j DROP

iptables -A tcpOUT -i $PRIVATE_INTERFACE -o $PUBLIC_INTERFACE -p tcp --dport 23 -j DROP
iptables -A tcpOUT -i $PRIVATE_INTERFACE -o $PUBLIC_INTERFACE -p tcp --sport 23 -j DROP

#Block all external traffic directed to ports 32768 – 32775, 137 – 139, TCP ports 111 and 515.
iptables -A tcpIN -i $PUBLIC_INTERFACE -o $PRIVATE_INTERFACE -p tcp -m multiport --dport 32768:32775,137:139,111,115 -j DROP

#Drop all TCP packets with the SYN and FIN bit set.
iptables -A tcpIN -i $PUBLIC_INTERFACE -o $PRIVATE_INTERFACE -p tcp --tcp-flags ALL ALL -j DROP


# ***************************
# 	PROTOCOL RULES
# ***************************

#TCP
    #forward packets, with allowed port, from public NIC to private network INCOMING
    iptables -A tcpIN -i $PUBLIC_INTERFACE -o $PRIVATE_INTERFACE -p tcp -m state --state NEW --sport 0:1023 -m multiport --dports $ALLOW_TCP -j DROP
    iptables -A tcpIN -i $PUBLIC_INTERFACE -o $PRIVATE_INTERFACE -p tcp -m state --state NEW,ESTABLISHED -m multiport --dports $ALLOW_TCP -j ACCEPT
    iptables -A tcpIN -i $PUBLIC_INTERFACE -o $PRIVATE_INTERFACE -p tcp -m state --state NEW,ESTABLISHED -m multiport --sports $ALLOW_TCP -j ACCEPT

    #forward packets, with allowed port, from private network to public NIC 
    iptables -A tcpOUT -i $PRIVATE_INTERFACE -o $PUBLIC_INTERFACE -p tcp -m multiport --dports $ALLOW_TCP -j ACCEPT
    iptables -A tcpOUT -i $PRIVATE_INTERFACE -o $PUBLIC_INTERFACE -p tcp -m multiport --sports $ALLOW_TCP -j ACCEPT

#UDP
    #forward packets, with allowed port, from public NIC to private network
    iptables -A udpIN -i $PUBLIC_INTERFACE -o $PRIVATE_INTERFACE -p udp --sport 0:1023 -m multiport --dports $ALLOW_UDP -j DROP
    iptables -A udpIN -i $PUBLIC_INTERFACE -o $PRIVATE_INTERFACE -p udp -m multiport --dports $ALLOW_UDP -j ACCEPT
    iptables -A udpIN -i $PUBLIC_INTERFACE -o $PRIVATE_INTERFACE -p udp -m multiport --sports $ALLOW_UDP -j ACCEPT

    #forward packets, with allowed port, from private network to public NIC
    iptables -A udpOUT -i $PRIVATE_INTERFACE -o $PUBLIC_INTERFACE -p udp -m multiport --dports $ALLOW_UDP -j ACCEPT
    iptables -A udpOUT -i $PRIVATE_INTERFACE -o $PUBLIC_INTERFACE -p udp -m multiport --sports $ALLOW_UDP -j ACCEPT

#ICMP
    #forward packets, with allowed port, from public NIC to private network
    iptables -A icmpIN -i $PUBLIC_INTERFACE -o $PRIVATE_INTERFACE -p icmp --icmp-type $ALLOW_ICMP  -j ACCEPT

    #forward packets, with allowed port, from private network to public NIC
    iptables -A icmpOUT -i $PRIVATE_INTERFACE -o $PUBLIC_INTERFACE -p icmp --icmp-type $ALLOW_ICMP -j ACCEPT



# ***************************
# 	   FORWARD
# ***************************

iptables -A FORWARD -p tcp -j tcpIN
iptables -A FORWARD -p tcp -j tcpOUT

iptables -A FORWARD -p udp -j udpIN
iptables -A FORWARD -p udp -j udpOUT

iptables -A FORWARD -p icmp -j icmpIN
iptables -A FORWARD -p icmp -j icmpOUT

#Accept fragments.
iptables -A FORWARD -f -j ACCEPT























