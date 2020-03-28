
import serial, time, sys, subprocess, os, ctypes, re
import paramiko
import datetime
import socket
import json
from scp import SCPClient
from datetime import datetime
import getpass
StartTime = datetime.now()

def Mbox(title, text, style):
    return ctypes.windll.user32.MessageBoxW(0, text, title, style)

def countdown(t):
    while t > 0:
        sys.stdout.write('\rTime remaining : {}s'.format(t))
        t -= 1
        sys.stdout.flush()
        time.sleep(1)


def send_message_to_slack(text):
    from urllib import request, parse
    import json

    post = {"text": "{0}".format(text)}

    try:
        json_data = json.dumps(post)
        req = request.Request("https://hooks.slack.com/services/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",
                              data=json_data.encode('ascii'),
                              headers={'Content-Type': 'application/json'})
        resp = request.urlopen(req)
    except Exception as em:
        print("EXCEPTION: " + str(em))


# # stdin, stdout, stderr = ssh.exec_command(f"sed -i 's/distance_to_sticker_th\": 0.01/distance_to_sticker_th\": 0.1/g' /usr/csr/etc/mfc_common.cfg")
from paramiko import SSHClient
class SSHClient_noauth(SSHClient):
    def _auth(self, username, *args):
        self._transport.auth_none(username)
        return

ssh =  SSHClient()
sshc = SSHClient_noauth()
sshc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
sshc.connect("10.10.33.133",username="root",password="")
stdin, stdout, stderr = sshc.exec_command("sed -i 's/distance_to_sticker_th\": 0.01/distance_to_sticker_th\": 0.1/g' /usr/csr/etc/mfc_common.cfg")
invfile = stdout.readlines()
print(invfile)
time.sleep(0.5)
calib_x=stdin, stdout, stderr = sshc.exec_command("cat /usr/csr/etc/prod.cfg | grep calib_x")
invfile = stdout.readlines()
print(invfile)
calib_x='\n'.join(invfile)
calib_x=''.join(c for c in calib_x if c.isdigit())
print(calib_x)
if calib_x!=0:
    print("GOOD")
else:
    print("BADDDD")
striped_list = [x.strip() for x in invfile]
ssh.close()
exit()




s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
# resetting script values
MFC_ID=""
Edit_ID_on_FW = ""
Edit_DNS_on_FW = ""
PSHostVersion="ver:1.1"
PSusername = getpass.getuser()

AnsibleHostValue=""
#check for ip
PSHostIP=s.getsockname()[0]
s.close()


# import subprocess
# proc = subprocess.check_output("ipconfig /all" ).decode('utf-8')
# print (proc)
# if "Forti" in proc:
#     print("User is connected through VPN, please disconnect and try again")
# exit()


# if not PSHostIP.startswith("10.10."or"10.11."or"10.12."):
#     print("Hello "+PSusername+" you are not connected to the right network, please connect to MFC's network and try again")
#     input("Press enter to exit ;)")
#     exit()
if PSHostIP.startswith("10.10."):
    MFC_ID="1"
    gateway_ip="10.10.31.254"
    Edit_ID_on_FW="5"
    Edit_DNS_on_FW="mfc1.csr"
    DeployerIP="10.50.0.6"
    Entry_Count_FW=1
    wpa_supplicant=br"""
        network={
                scan_ssid=1
                bgscan=\"simple:5:-59:500\"
                scan_freq=2412 2437 2462
                ssid=\"MFC1R\"
                psk=\"hanegev6\"
        }
        """
if PSHostIP.startswith("10.11."):
    MFC_ID="0"
    gateway_ip="10.5.0.115"
    Edit_ID_on_FW="2"
    Edit_DNS_on_FW="mfc0"
    DeployerIP="10.11.31.131"
    Entry_Count_FW =1
    wpa_supplicant=br"""
        network={
                scan_ssid=1
                bgscan=\"simple:5:-65:500\"
                scan_freq=2412 2437 2462
                ssid=\"MFC0R\"
                psk=\"csrsic2019\"
        }
        """
if PSHostIP.startswith("10.12."):
    MFC_ID="2"
    gateway_ip="10.12.40.254"
    Edit_ID_on_FW="2"
    Edit_DNS_on_FW="MFC2"
    DeployerIP="10.51.0.4"
    Entry_Count_FW = 20
    # RabbitIP=br"""
    # {
    # \"rabbit_ip\"=\"10.12.32.100\"
    # }
    # """
    wpa_supplicant=br"""
        network={
                    scan_ssid=1
                    bgscan=\"simple:5:-59:500\"
                    scan_freq=2412 2437 2462
                    ssid=\"MFC2R\"
                    psk=\"hanegev7\"
        }
        """

print("Hello "+PSusername+" and welcome to Fabric robots automation tool!  Your IP Address is: "+PSHostIP+" You are on MFC:"+MFC_ID)
# Check if script version is suitable


ssh_host = DeployerIP
ssh_port = 22
ssh_user = "csr_user"
ssh_password = "csr_user"
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(ssh_host, username=ssh_user, password=ssh_password)
stdin, stdout, stderr = ssh.exec_command(f"grep -F '{PSHostVersion}' /opt/csr/FastAutomationDeployingScriptVersion")
response = stdout.readlines()
if len(response)==0:
    print("Wrong version! cannot proceed, Updated version will be downloaded automatically to your directory, plesse use this.")
    Mbox('ERROR!! ERROR!! ERROR!!', 'Wrong version! Updated version will be downloaded automatically to current directory named AutomaticDeployLatestVersion.zip,, please use this', 1)
    scp=SCPClient(ssh.get_transport())
    scp.get("/opt/csr/AutomaticDeployingLatestVersion.zip")
    os.system("FastAutomationDeployingScript")
    # os.remove('c:\Users\eden.mor\Desktop\python.py')
    ssh.close()
    exit()
else:
    print("Good version! proceeding with deployment")
ssh.close()


# initialization and open the port
import serial.tools.list_ports
ports = serial.tools.list_ports.comports()
ComPortToConnect = ""
for port, desc, hwid in sorted(ports):
        # print("{}: {} [{}]".format(port, desc, hwid))
        if (desc.find("Standard") == -1):
            print("")
        else:
            ComPortToConnect = port
print("Standard COM Port to connect:"+ComPortToConnect)

robot_filename = b"/etc/wpa_supplicant.conf"
# robot_rabbitpath=b"/usr/csr/etc/mfc_common.cfg"
robot_hostname = b"/etc/hostname"


ser = serial.Serial()
ser.port = ComPortToConnect
print(ComPortToConnect)
ser.baudrate = 115200
ser.bytesize = serial.EIGHTBITS #number of bits per bytes
ser.parity = serial.PARITY_NONE #set parity check: no parity
ser.stopbits = serial.STOPBITS_ONE #number of stop bits
#ser.timeout = None          #block read
ser.timeout = 1            #non-block read
#ser.timeout = 2              #timeout block read
ser.xonxoff = False     #disable software flow control
ser.rtscts = False     #disable hardware (RTS/CTS) flow control
ser.dsrdtr = False       #disable hardware (DSR/DTR) flow control
ser.writeTimeout = 1     #timeout for write

try:
    ser.open()
except Exception as e:
    print ("error open serial port: " + str(e))
    Mbox('Error!', 'Error open serial port, check if cable is connected ', 2)
    exit()

if ser.isOpen():

    try:
        ser.flushInput() #flush input buffer, discarding all its contents
        ser.flushOutput()#flush output buffer, aborting current output
        #and discard all that is in buffer

        #write data
        print("login as root")
        ser.write(b'root\r\n')
        time.sleep(0.4)
        ser.flushInput()  # flush input buffer, discarding all its contents
        ser.flushOutput()  # flush output buffer, aborting current output

        ser.write(b'echo "' + wpa_supplicant + b'" > ' + robot_filename + b'\r\n')
        time.sleep(1)
        ser.flushInput()
        ser.flushOutput()
        time.sleep(2)
        ser.write(b'kill  -9  `pidof wpa_supplicant`\r\n')
        response=ser.readline()
        ser.flushInput()
        time.sleep(2)
        ser.write(b'wpa_supplicant -B -Dnl80211 -i wlan0 -c /etc/wpa_supplicant.conf\r\n')
        response=ser.readline()
        ser.flushInput()
        time.sleep(2)
        response=ser.readline()
        ser.write(b'udhcpc -i wlan0\r\n')
        time.sleep(1)
        print("Successfully configured wpa_supllicant.conf file, please wait 30 seconds")
        #ser.write(b'sudo reboot\r\n')
        # time.sleep(4)  #give the serial port sometime to receive the data
        #countdown(120)
        # if ser.isOpen():
        #     print("Robot was restarted successfully! IP address, MAC and Hostname will now be taken automatically")
        #     ser.write(b'root\r\n')
        # else:
        #     ser.open()
        #     ser.write(b'root\r\n')
        countdown(30)
        numOfLines = 0
        macbeforecut = ""
        ipbeforecut = ""
        ser.flushInput()
        response=""
        ser.write(b'\r\n')
        while True: #retrive ip and mac
            ser.write(b'ifconfig wlan0\r\n')
            time.sleep(0.6)
            response = ser.readline()
            # print(b"read data: " + response)
            if b'HWaddr' in response:
                i = response.find(b'HWaddr') + 7
                macbeforecut = response[i:i+17]
                converttostr = macbeforecut.decode("utf-8")
                mac = converttostr.split("'")[0]
                # print("**********THIS IS THE MAC ADDRESS:", mac+"**********")
            if b'inet addr' in response:
                i = response.find(b'inet addr') + 10
                ipbeforecut = response[i:i+12]
                converttostrIP = ipbeforecut.decode("utf-8")
                ip = converttostrIP.split("'")[0]
                # print("**********THIS IS THE IP ADDRESS:", ip+"**********")
            numOfLines = numOfLines + 1
            if (numOfLines >= 9):
                break
        time.sleep(1)
        numOfLines = 0
        ser.flushInput()
        time.sleep(1)
        ser.write(b'cat /etc/hostname\r\n') #retrive hostname
        time.sleep(1)
        while True:
            response = ser.readline()
            if b'root@' in response:
                i = response.find(b'root@') + 5
                hostnameBeforeCut = response[i:i+11]
                converttostrHostname = hostnameBeforeCut.decode("utf-8")
                hostname = converttostrHostname.split("@")[0]
                # print("**********THIS IS THE HOSTNAME:", hostname+"**********")``
            if (numOfLines >= 10):
                break
            numOfLines = numOfLines + 1
        GrepForNumbersHostname = ''.join(c for c in hostname if c.isdigit())
        if not (hostname.startswith("LRS") or hostname.startswith("GR")): #Correct LRS hostnames automatically
            GrepForNumbersHostname = GrepForNumbersHostname.encode("utf-8")
            hostname=b'LRS' + GrepForNumbersHostname
            # hostname = hostname.encode("utf-8") # convert from str to bytes
#            print(b"New automatically corrected hostname: "+hostname)
            time.sleep(0.5)
            # ser.flushOutput()
            # ser.flushInput()
            time.sleep(0.4)
            ser.write(b'echo "' + hostname + b'" > ' + robot_hostname + b'\r\n')
            hostname = hostname.decode("utf-8") # turn back to string
            GrepForNumbersHostname=GrepForNumbersHostname.decode("utf-8")
            time.sleep(1)
            ser.write(b'reboot\r\n')
            print("Robot hostname was reconfigured, rebooting again for applying changes, please wait 105 seconds")
            countdown(105)
            print(hostname)
        else:
            hostname=hostname
        ser.write(b'exit\r\n')
        ser.close()
    except Exception as e1:
        print("error communicating...: " + str(e1))

else:
    print("cannot open serial port ")

HostnameToDeployer=""
HostnameToFW=""
ip=re.findall( r'[0-9]+(?:\.[0-9]+){3}',ip)
ip=' '.join([str(elem) for elem in ip])
if "LR" in hostname:
    HostnameToDeployer="LRS" + GrepForNumbersHostname
    HostnameToFW="LR" + GrepForNumbersHostname[-4:]
else:
    HostnameToDeployer=hostname[0:6]
    HostnameToFW=hostname[0:6]
print(f"***Robot details***, Robot hostname is : {HostnameToDeployer}, IP address is :{ip}, MAC address is: {mac}")
# Update your Fortigate IP Address Here
#FortiGate IP's : MFC0= 10.11.31.254     MFC1= 10.10.31.254   MFC2=10.10.40.254


def check_ping(hostname):

    response = os.system("ping  " + HostnameToFW)
    # and then check the response...
    if response == 0 :
        pingstatus = "Robot has DNS"
    else:
        pingstatus = "Network Error"

    return pingstatus
check=check_ping(HostnameToFW)
print("Validating Robot DNS:\n")
if "Error" in check: #check if robot is configured for DNS
    print("Configuring Robot DNS & DHCP")
    netmask = "255.255.255.255"
    def connect_to_server(server="192.168.1.99", username="admin", password="admin", command=""):
        ssh = paramiko.SSHClient()
        ssh.connect(server, username=username, password=password)

        return ssh.exec_command(command)


    def agent_auth(transport, username):
        """
        Attempt to authenticate to the given transport using any of the private
        keys available from an SSH agent.
        """

        agent = paramiko.Agent()
        agent_keys = agent.get_keys()
        if len(agent_keys) == 0:
            return

        for key in agent_keys:
            #        print('Trying ssh-agent key {}'.format(hexlify(key.get_fingerprint()))),
            try:
                transport.auth_publickey(username, key)
                print('... success!')
                return
            except paramiko.SSHException:
                print('... nope.')


    def group_by_section(content, match):
        buffer = []
        for line in content:
            line = line.strip()
            line = line.replace("--More-- \r         \r            ", "")
            if line.startswith("config") or line == "end":
                if buffer: yield buffer
                buffer = [line]
            else:
                buffer.append(line)
        yield buffer


    def get_config_value(config, find):
        for line in config:
            line = line.strip()
            line = line.replace("--More-- \r         \r            ", "")
            if line.startswith(find):
                found = line.replace(find, "")
                return found.split(" ")


    """ <Main> Init """
    if __name__ == "__main__":

        devicename = HostnameToFW
        ipaddress = ip
        macaddress = mac

        """ !! Print Message """
        print("Initiating Fortinet Reserved DHCP Address\n")

        """ SSH Connect To Device """
        print("Connecting to Device: %s" % gateway_ip)

        """  """
        ssh_host = gateway_ip
        ssh_port = 22
        ssh_user = "Eden"
        ssh_password = "Matrix1234!"  # // We use SSH key instead
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, username=ssh_user, password=ssh_password)

        stdin, stdout, stderr = ssh.exec_command('show system dhcp server '+Edit_ID_on_FW)
        fortigate_config = stdout.readlines()

        # Create int holders
        last_entry = 0
        max_entry = 0
        entry_count = 0
        entry = 1
        description = ""
        entry_found = False

        # counter=0
        # for sections in group_by_section():
        #     counter+=1


        # Loop through the retrieved data
        for sections in group_by_section(fortigate_config, 'reserved-address'):
            if (sections[0] == "config reserved-address"):
                for config in sections:
                    config = config.lstrip()
                    if config.startswith("edit"):
                        entry = config.split()[1]
                        last_entry = int(entry)
                        max_entry = max(max_entry, last_entry)

                        entry_count = entry_count + 1
                    elif entry != 0:
                        if config.startswith("set description"):
                            description = config.split()[2]
                            if description == '"'+devicename+'"':
                                print("Device Name already exists (ID: %d)" % last_entry)
                                entry_found = True
                                break
                        if macaddress in config:
                            print("MAC Address is already reserved In Entry %d (%s)" % (last_entry, description))
                            entry_found = True
                            break
                        if ipaddress in config:
                            print("IP Address is already reserved In Entry %d (%s)" % (last_entry, description))
                            entry_found = True
                            break

        interface = get_config_value(fortigate_config, "set interface")[1].replace('"', "")

        # Allocate Next Entry
        #next_entry = entry_count + Entry_Count_FW
        next_entry = last_entry if entry_found else max_entry + 1
        print("We found %d entries" % entry_count)
        print("Our next entry will be: %d" % next_entry)
        print("Loading template")
        template = open("dhcp_template.erb", "r").read()
        result = template.format(Edit_DNS_on_FW=Edit_DNS_on_FW,Edit_ID_on_FW=Edit_ID_on_FW,ID=next_entry, DEVICENAME=HostnameToFW, IPADDRESS=ipaddress, NETMASK=netmask,MACADDRESS=macaddress, INTERFACE=interface)
        print("Pushing Config:")
        print(result)

        stdin, stdout, stderr = ssh.exec_command(result)
        response = stdout.read()

    #    if response.find("Can not set duplicate entry."):
    #        print("[Error!] Found a duplicate entry")


        print("\nFinished configuring DHCP and DNS!")

        ssh.close()
        time.sleep(1)
else:
    print("Robot is already configured for DNS Proceeding to update command")
if "GR" in hostname:
    AnsibleHostValue = HostnameToDeployer + " ansible_host=" + ip + " robot_gen=gen2 image_filename=GR_release.tar.gz"
else:
    AnsibleHostValue = HostnameToDeployer + " ansible_host=" + ip

x = "wpa_supplicant and FW settings finished for "+HostnameToFW +" MAC Address=" +mac +" IP Address=" +ip+", on MFC:"+MFC_ID +"Username: " +PSusername +"PS Host version"+PSHostVersion+"UserIP"+PSHostIP
send_message_to_slack(x)
with open("Robots_after_deploy.txt", "a") as robotlog:

    robotlog.write("Hostname="+HostnameToFW +"  MAC Address="+mac +" IP Address="+ip+", on MFC: "+MFC_ID)
    robotlog.write("\n")

# Deployer IP
# ssh_host = "10.50.0.6"
# Deployer IP's: MFC0=10.21.0.25    MFC1=10.50.0.6    MFC2=10.51.0.4
ssh_port = 22
ssh_user = "csr_user"
ssh_password = "csr_user"
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(DeployerIP, username=ssh_user, password=ssh_password)
stdin, stdout, stderr = ssh.exec_command(f"grep -F '{HostnameToDeployer}' /opt/csr/inv/mfc{MFC_ID}.inv")
invfile = stdout.readlines()
striped_list = [x.strip() for x in invfile]
if len(striped_list)!=0:
    print("Hostname entry "+HostnameToDeployer+" allready exsits in INV file! Rewriting entry")
    stdin, stdout, stderr = ssh.exec_command(f"sed -i '/{HostnameToDeployer}/d' /opt/csr/inv/mfc{MFC_ID}.inv") # deleting current entry from inv file
    if "LR" in HostnameToDeployer:
        stdin, stdout, stderr = ssh.exec_command(f"sed -i '/^\[lifts\]/a {AnsibleHostValue}' /opt/csr/inv/mfc{MFC_ID}.inv")
    else:
        stdin, stdout, stderr = ssh.exec_command(f"sed -i '/^\[grounds\]/a {AnsibleHostValue}' /opt/csr/inv/mfc{MFC_ID}.inv")
    print("Update Playbook- Please wait about 1 minute")
    stdin, stdout, stderr = ssh.exec_command(f"export CSR_ENVTYPE=Dev && export INV_FILE=mfc{MFC_ID}.inv && source /opt/csr/deployer_host_scripts.sh && ddtool-playbook playbooks/csr/update_robots.yml -l {HostnameToDeployer}",get_pty=True)
    response = stdout.readlines()
    print('\n'.join(response))
    stdin, stdout, stderr = ssh.exec_command(f"export CSR_ENVTYPE=Dev && export INV_FILE=mfc{MFC_ID}.inv && source /opt/csr/deployer_host_scripts.sh && ddtool-adhoc {HostnameToDeployer} -m copy -a 'src=/opt/csr_deployment/playbooks/local/wpa_supplicant.conf dest=/etc/wpa_supplicant.conf'",get_pty=True)
    response = stdout.readlines()
    print('\n'.join(response))
    print("robot is now rebooting, when its back again you can insert it to robotland")
    time.sleep(1)
    stdin, stdout, stderr = ssh.exec_command(f"export CSR_ENVTYPE=Dev && export INV_FILE=mfc{MFC_ID}.inv && source /opt/csr/deployer_host_scripts.sh && ddtool-playbook playbooks/csr/reboot.yml -l {HostnameToDeployer}",get_pty=True)
    response = stdout.readlines()
    print('\n'.join(response))
    Mbox('====Finished deploying robot!===', 'You can now insert it to robotland!', 1)
    ssh.close()
else:
    if "GR" in HostnameToDeployer:
        stdin, stdout, stderr = ssh.exec_command(f"sed -i '/^\[grounds\]/a {AnsibleHostValue}' /opt/csr/inv/mfc{MFC_ID}.inv")
        print(AnsibleHostValue + " was added successfully to inv file!")
        time.sleep(2)
        print("Update Playbook- Please wait about 1 minute")
        stdin, stdout, stderr = ssh.exec_command(f"export CSR_ENVTYPE=Dev && export INV_FILE=mfc{MFC_ID}.inv && source /opt/csr/deployer_host_scripts.sh && ddtool-playbook playbooks/csr/update_robots.yml -l {HostnameToDeployer}" , get_pty=True)
        response = stdout.readlines()
        print('\n'.join(response))
        stdin, stdout, stderr = ssh.exec_command(f"export CSR_ENVTYPE=Dev && export INV_FILE=mfc{MFC_ID}.inv && source /opt/csr/deployer_host_scripts.sh && ddtool-adhoc {HostnameToDeployer} -m copy -a 'src=/opt/csr_deployment/playbooks/local/wpa_supplicant.conf dest=/etc/wpa_supplicant.conf'",get_pty=True)
        response = stdout.readlines()
        print('\n'.join(response))
        print("robot is now rebooting, when its back again you can insert it to robotland")
        Mbox('Finished deploying robot!', 'Finished! you can now insert the robot to robotland', 1)
    else:
        stdin, stdout, stderr = ssh.exec_command(f"sed -i '/^\[lifts\]/a {AnsibleHostValue}' /opt/csr/inv/mfc{MFC_ID}.inv")
        print(AnsibleHostValue + " was added successfully to inv file!")
        Mbox('Success!', 'Successfully added hostname to INV file!', 1)
        time.sleep(1)
        print("Update Playbook- Please wait about 1 minute")
        stdin, stdout, stderr = ssh.exec_command(f"export CSR_ENVTYPE=Dev && export INV_FILE=mfc{MFC_ID}.inv && source /opt/csr/deployer_host_scripts.sh && ddtool-playbook playbooks/csr/update_robots.yml -l {HostnameToDeployer}",get_pty=True)
        response = stdout.readlines()
        print('\n'.join(response))
        print("robot is now rebooting, when its back again you can insert it to robotland")
        stdin, stdout, stderr = ssh.exec_command(f"export CSR_ENVTYPE=Dev && export INV_FILE=mfc{MFC_ID}.inv && source /opt/csr/deployer_host_scripts.sh && ddtool-playbook playbooks/csr/reboot.yml -l {HostnameToDeployer}",get_pty=True)
        print('\n'.join(response))
ssh.close()

print("Writing to Slack  #robots_after_deploy_test channel")
x = "Deploy finished for "+HostnameToFW +" MAC Address=" +mac +" IP Address=" +ip+", on MFC:"+MFC_ID +"Username: " +PSusername +"PS Host version"+PSHostVersion+"UserIP"+PSHostIP
send_message_to_slack(x)
print("Finished! you can now insert the robot to robotland!")
input("Press Enter to exit ;)")
exit()
