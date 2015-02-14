#		internalTestScript.rb
#This script should only be run on internal devices.
#It's purpose is to test packets outbound from the network.
#
# **************************************************
# 	   USER CONFIGURABLE SECTION
# **************************************************

#UTILITY_NAME = 'internalTestScript'
#UTILITY_LOCATION = '/usr/sbin/'
INTERNAL_ADDR='192.168.10.2'
FIREWALL_ADDR='192.168.0.15'
EXTERNAL_ADDR='192.168.0.22'

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
	system("hping #{EXTERNAL_ADDR} -S -s 2000 -p #{tcpPort} -c #{PACKET_COUNT} -i #{SEND_SPEED}")
end


#test UDP ports
warn "\n-----------------------------------------------------"
warn "Allowed UDP ports started. -- One way transmission - no syn/ack backs"
warn "-----------------------------------------------------"
for udpPort in ALLOW_UDP;
	warn "\nTesting Incoming packets on Allowed UDP Port #{udpPort}"
	system("hping #{EXTERNAL_ADDR} --udp -s 2000 -k -p #{udpPort} -c #{PACKET_COUNT} -i #{SEND_SPEED}")
end


#test ICMP ports
warn "\n-----------------------------------------------------"
warn "Allowed ICMP ports started. -- One way transmission - no syn/ack backs\n"
warn "-----------------------------------------------------"
for icmpPort in ALLOW_ICMP;
	warn "\nTesting Incoming packets on Allowed ICMP Type #{icmpPort}"
	system("hping #{EXTERNAL_ADDR} --icmpcode #{ALLOW_ICMP} -c #{PACKET_COUNT} -i #{SEND_SPEED}")
end


#test default is to drop packets
warn "\n-----------------------------------------------------"
warn "Default to drop packets started. -- All packets drop\nhping #{EXTERNAL_ADDR} -s 2000 -k -S -p 900 -c #{PACKET_COUNT} -i #{SEND_SPEED}"
warn "-----------------------------------------------------"
system("hping #{EXTERNAL_ADDR} -s 2000 -k -S -p 900 -c #{PACKET_COUNT} -i #{SEND_SPEED}")



#Accept fragments
warn "\n-----------------------------------------------------"
warn "Accept fragments started. -- Ack back\nhping #{EXTERNAL_ADDR} -f -s 2000 -k -p 80 -c #{PACKET_COUNT} -i #{SEND_SPEED}"
warn "-----------------------------------------------------"
system("hping #{EXTERNAL_ADDR} -f -s 2000 -k -p 80 -c #{PACKET_COUNT} -i #{SEND_SPEED}")


#Drop packets with SYN & FIN
warn "\n-----------------------------------------------------"
warn "Drop packets with SYN & FIN started. -- All packets drop\nhping #{EXTERNAL_ADDR} -S -F -s 2000 -k -p 80 -c #{PACKET_COUNT} -i #{SEND_SPEED}"
warn "-----------------------------------------------------"
system("hping #{EXTERNAL_ADDR} -S -F -s 2000 -k -p 80 -c #{PACKET_COUNT} -i #{SEND_SPEED}")


#Drop telnet packets
warn "\n-----------------------------------------------------"
warn "Drop telnet packets started. -- All packets drop\nhping #{EXTERNAL_ADDR} -S -s 2000 -k -p 23 -c #{PACKET_COUNT} -i #{SEND_SPEED}"
warn "-----------------------------------------------------"
system("hping #{EXTERNAL_ADDR} -S -s 2000 -k -p 23 -c #{PACKET_COUNT} -i #{SEND_SPEED}")



warn "\n-----------------------------------------------------"
warn "All external --> internal packet tests complete!"
warn "-----------------------------------------------------"



