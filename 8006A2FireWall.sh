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

#UTILITY_NAME
#UTITLITY_LOCATION
#INTERNAL_NET_ADDR
#EXTERNAL_ADDR

ALLOW_TCP=(53 67 68 80 443)
#ALLOW_UDP=()
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
iptables -X


iptables -N trafficTCP -j ACCEPT
iptables -N trafficUDP -j ACCEPT
iptables -N trafficICMP -j ACCEPT

for tcpPort in ${ALLOW_TCP[*]}
do
    iptables -A OUPUT -p tcp --dport $tcpPort -j trafficTCP
    iptables -A INPUT -p tcp --sport $tcpPort -j trafficTCP
done

#for tcpPort in ${ALLOW_UDP[*]}
#do
#    iptables -A INPUT -p tcp --dport $tcpPort -j trafficTCP
#done

#for tcpPort in ${ALLOW_ICMP[*]}
#do
#    iptables -A INPUT -p tcp --dport $tcpPort -j trafficTCP
#done



