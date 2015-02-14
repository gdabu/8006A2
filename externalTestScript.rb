#		externalTestScript.rb
#This script should only be run on external devices.
#It's purpose is to test packets inbound to the network.
#
# **************************************************
# 	   USER CONFIGURABLE SECTION
# **************************************************

#UTILITY_NAME = 'externalTestScript'
#UTILITY_LOCATION = '/usr/sbin/'
INTERNAL_ADDR='192.168.10.2'
FIREWALL_ADDR='192.168.0.15'

ALLOW_TCP=[22,53,67,68,80,443]
ALLOW_UDP=[53,67,80,443]
ALLOW_ICMP=[8]

PACKET_COUNT=20
SEND_SPEED='u500' #Microseconds


# **************************************************
# 	IMPLEMENTATION SECTION - DO NOT TOUCH
# **************************************************

#redirect stdout to log file
File.open("log", "w+")
$stdout.reopen("log", "a+")
$stderr.reopen("log", "a+")

#test TCP ports
warn "\n-----------------------------------------------------"
warn "Allowed TCP ports started. -- No packet loss"
warn "-----------------------------------------------------"
for tcpPort in ALLOW_TCP;
	warn "\nTesting Incoming packets on Allowed TCP Port #{tcpPort}"
	system("hping #{FIREWALL_ADDR} -S -s 2000 -p #{tcpPort} -c #{PACKET_COUNT} -i #{SEND_SPEED}")
end


#test UDP ports
warn "\n-----------------------------------------------------"
warn "Allowed UDP ports started. -- One way transmission - no syn/ack backs"
warn "-----------------------------------------------------"
for udpPort in ALLOW_UDP;
	warn "\nTesting Incoming packets on Allowed UDP Port #{udpPort}"
	system("hping #{FIREWALL_ADDR} --udp -s 2000 -k -p #{udpPort} -c #{PACKET_COUNT} -i #{SEND_SPEED}")
end


#test ICMP ports
warn "\n-----------------------------------------------------"
warn "Allowed ICMP ports started. -- One way transmission - no syn/ack backs\n"
warn "-----------------------------------------------------"
for icmpPort in ALLOW_ICMP;
	warn "\nTesting Incoming packets on Allowed ICMP Type #{icmpPort}"
	system("hping #{FIREWALL_ADDR} --icmpcode #{ALLOW_ICMP} -c #{PACKET_COUNT} -i #{SEND_SPEED}")
end


#test default is to drop packets
warn "\n-----------------------------------------------------"
warn "Default to drop packets started. -- All packets drop\nhping #{FIREWALL_ADDR} -s 2000 -k -S -p 900 -c #{PACKET_COUNT} -i #{SEND_SPEED}"
warn "-----------------------------------------------------"
system("hping #{FIREWALL_ADDR} -s 2000 -k -S -p 900 -c #{PACKET_COUNT} -i #{SEND_SPEED}")


#Drop packets with internal source address, coming from outside the network
warn "\n-----------------------------------------------------"
warn "Drop packets with internal source address, coming from outside the network started. -- All packets drop\nhping #{FIREWALL_ADDR} -a #{INTERNAL_ADDR} -s 2000 -k -S -p 80 -c #{PACKET_COUNT} -i #{SEND_SPEED}"
warn "-----------------------------------------------------"
system("hping #{FIREWALL_ADDR} -a #{INTERNAL_ADDR} -s 2000 -k -S -p 80 -c #{PACKET_COUNT} -i #{SEND_SPEED}")


#Drop incoming SYN packets with destination port > 1024
warn "\n-----------------------------------------------------"
warn "Drop incoming SYN packets with destination port > 1024 started. -- All packets drop\nhping #{FIREWALL_ADDR} -s 2000 -k -S -p 2222 -c #{PACKET_COUNT} -i #{SEND_SPEED}"
warn "-----------------------------------------------------"
system("hping #{FIREWALL_ADDR} -s 2000 -k -S -p 2222 -c #{PACKET_COUNT} -i #{SEND_SPEED}")


#Accept fragments
warn "\n-----------------------------------------------------"
warn "Accept fragments started. -- Ack back\nhping #{FIREWALL_ADDR} -f -s 2000 -k -p 80 -c #{PACKET_COUNT} -i #{SEND_SPEED}"
warn "-----------------------------------------------------"
system("hping #{FIREWALL_ADDR} -f -s 2000 -k -p 80 -c #{PACKET_COUNT} -i #{SEND_SPEED}")


#Drop packets with SYN & FIN
warn "\n-----------------------------------------------------"
warn "Drop packets with SYN & FIN started. -- All packets drop\nhping #{FIREWALL_ADDR} -S -F -s 2000 -k -p 80 -c #{PACKET_COUNT} -i #{SEND_SPEED}"
warn "-----------------------------------------------------"
system("hping #{FIREWALL_ADDR} -S -F -s 2000 -k -p 80 -c #{PACKET_COUNT} -i #{SEND_SPEED}")


#Drop telnet packets
warn "\n-----------------------------------------------------"
warn "Drop telnet packets started. -- All packets drop\nhping #{FIREWALL_ADDR} -S -s 2000 -k -p 23 -c #{PACKET_COUNT} -i #{SEND_SPEED}"
warn "-----------------------------------------------------"
system("hping #{FIREWALL_ADDR} -S -s 2000 -k -p 23 -c #{PACKET_COUNT} -i #{SEND_SPEED}")


#Drop incoming packets coming to ports 111, 137, 138, 139, 32768-32775
warn "\n-----------------------------------------------------"
warn "Drop incoming packets coming to ports 111 started."
warn "-----------------------------------------------------"
system("hping #{FIREWALL_ADDR} -S -s 2000 -k -p 111 -c #{PACKET_COUNT} -i #{SEND_SPEED}")
warn "\n-----------------------------------------------------"
warn "Drop incoming packets coming to ports 137-139 started."
warn "-----------------------------------------------------"
system("hping #{FIREWALL_ADDR} -S -s 2000 -k -p 137 -c #{PACKET_COUNT} -i #{SEND_SPEED}")
system("hping #{FIREWALL_ADDR} -S -s 2000 -k -p 138 -c #{PACKET_COUNT} -i #{SEND_SPEED}")
system("hping #{FIREWALL_ADDR} -S -s 2000 -k -p 139 -c #{PACKET_COUNT} -i #{SEND_SPEED}")
warn "\n-----------------------------------------------------"
warn "Drop incoming packets coming to ports 32768-32775 started."
warn "-----------------------------------------------------"
system("hping #{FIREWALL_ADDR} -S -s 2000 -k -p 32768 -c #{PACKET_COUNT} -i #{SEND_SPEED}")
system("hping #{FIREWALL_ADDR} -S -s 2000 -k -p 32769 -c #{PACKET_COUNT} -i #{SEND_SPEED}")
system("hping #{FIREWALL_ADDR} -S -s 2000 -k -p 32770 -c #{PACKET_COUNT} -i #{SEND_SPEED}")
system("hping #{FIREWALL_ADDR} -S -s 2000 -k -p 32771 -c #{PACKET_COUNT} -i #{SEND_SPEED}")
system("hping #{FIREWALL_ADDR} -S -s 2000 -k -p 32772 -c #{PACKET_COUNT} -i #{SEND_SPEED}")
system("hping #{FIREWALL_ADDR} -S -s 2000 -k -p 32773 -c #{PACKET_COUNT} -i #{SEND_SPEED}")
system("hping #{FIREWALL_ADDR} -S -s 2000 -k -p 32764 -c #{PACKET_COUNT} -i #{SEND_SPEED}")
system("hping #{FIREWALL_ADDR} -S -s 2000 -k -p 32775 -c #{PACKET_COUNT} -i #{SEND_SPEED}")


warn "\n-----------------------------------------------------"
warn "All external --> internal packet tests complete!"
warn "-----------------------------------------------------"



