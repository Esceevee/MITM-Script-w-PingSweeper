import multiprocessing
import subprocess
import os

# Capture output of the ifconfig command
ipconf = subprocess.check_output(["ifconfig"])

# ...Then just get this machine IP by looking through the string
thisIP = ipconf[ipconf.index("inet")+5:ipconf.index("netmask")].strip()

# Print this machine IP in a nice format
print("Your local IP Address is: " + thisIP)

# Get information about the network where this computer reside with an 'ip r' command
ipR= subprocess.check_output(["ip", "r"])

# ...Then just get the network's gateway by looking through the string
gateway = ipR[ipR.index("via")+3:ipR.index("dev")].strip()

# Print this network's gateway in a nice format
print("Your gateway IP Address is: " + gateway)

# Let the user know that we will look for targets now.
print
print "Finding Potential Targets..."

# list of the targets to ping.We construvt this by gettting the network where the user resides. We will use string manipulation for this...
pingTargets = thisIP[:-1:]

# This list will only contain the succesful pings
pings = []

# This dic will contain IPs keys with MAC addresses as values
targetAddresses = {}

# These IP addresses will be joined to correspoding MAC addresses once we find them
IPAddresses = []

# The MAC addresses if the IPs that we will look for.
MACAddresses =[]

# This funcion pings as many times as long a we keep finding a 'job' to do
# Note that we will be pinging 3 times per IP
def pinger( job_q, results_q ):
	DEVNULL = open(os.devnull,'w')
	while True:
		ip = job_q.get()
		if ip is None: break
		try:
			subprocess.check_output(['ping','-c','3',ip])
			results_q.put(ip)
			print ("...")
		except:
			pass

# How many proccesses we'll be using
pool_size = 255

# Queue the jibs and their result
jobs = multiprocessing.Queue()
results = multiprocessing.Queue()

# Start pooling the pings
pool = [ multiprocessing.Process(target=pinger, args=(jobs,results))
	for i in range(pool_size) ]

for p in pool:
	p.start()

# Ping the 255 (-1) targets
for i in range(1,255):
	jobs.put(pingTargets + str(i))
# Signal that there are no more jibs to do
for p in pool:
	jobs.put(None)

# Run as one
for p in pool:
	p.join()

# We check the arp table to see fetch our results
arpOutput = subprocess.check_output(["arp", "-a"])

# We split the results by line...
arpOutputSplit = arpOutput.split("\n")

# We ingnore the incomplete pings
for i in arpOutputSplit:
	if("<incomplete>" not in i):
		pings.append(i)
# We format pings by spaces. This will get us IPs and MACs
pingsList = " ".join(pings)

# ...We then split them away from the list so we can rebuild it neatly as a dictionary
# ... We shall then go to build the MITM attack on the MITM.py script...
arpOutputSplit = pingsList.split(" ")
for i in arpOutputSplit:
	if("." in i):
		IPAddresses.append(i[1:-1].strip())
	elif(":" in i):
		MACAddresses.append(i.strip())
	targetAddresses = dict(zip(IPAddresses, MACAddresses))