# SimL2tp configure file


#########################
#  User Info Configure  #
#########################

# username
username = @USERNAME@


# the password to pass to authen
# it is not recommended to provide password here
# you can provide by command line( still unsafe ),
# configure it in pap-secret file
# or better by interactive input
# 
password = @PASSWORD@


# normally you'll auto provide your hosname(not username) to l2tp server
# if you do not like this(for any reason), just give a alias name as you like
#hostname = ticty



######################
#  Server Configure  #
######################

# special the outgoing interface
# ip address or device name
# only accept once
#interface = wlan0
#interface = eth0
#interface = 10.10.10.10


# authen server host address, with port number
# for most l2tp server, port is 1701 ( INAN regedited )
host = @HOST@
#host = 10.255.201.4:1701


# LAN route table
# it will add to route table before ppp start
# AHUT may refer to "jnaas.ahut.edu.cn/selfservice/custom/right/ru.txt"
add route = @ROUTE@
#add route = 10.0.0.0		255.0.0.0
#add route = 110.0.0.0		255.0.0.0
#add route = 172.16.0.0		255.240.0.0
#add route = 192.168.0.0		255.255.224.0
#add route = 222.195.32.0	255.255.224.0
#add route = 210.45.56.0		255.255.248.0
#add route = 211.70.144.0	255.255.240.0



########################
#  SimL2tp configures  #
########################

# if run in daemon mode
daemon = 1


# max re-send times for reliable transmission
max_re_send = 5


# pppd path
ppp path = @PPPD@

# ppp config
# default is at $HOME/.siml2tp/ppp.conf
#ppp config = 

# ppp plugins path
# default is at $HOME/.siml2tp/passwordfd.so
#passwordfd = 


# receive windows size
rws = 4


