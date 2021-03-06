import json
import socket
import select
from threading import Thread
from time import sleep
from datetime import datetime
import base64
import subprocess
from zipfile import ZipFile
import platform
import os
import configparser

ip_address = ""
port = 12345

encoding = "utf-8"
flyingPackages = {}
receiveWindow = 1
packageSize = 1500
ackPackages = []

system_type = ""
server_ip = ""
user_ip = ""
wifi_ssid = ""

def get_ip():
    global ip_address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
    finally:
        s.close()

"""
def create_message(message_type, body=""):
    global ip_address
    message = {}
    if message_type == 1:
        curr_dt = datetime.now()
        timestamp = int(round(curr_dt.timestamp()))
        message = {"IP": ip_address, "type": message_type, "ID": timestamp}
    elif message_type == 2:
        message = {"IP": ip_address, "type": message_type}
    elif message_type == 3:
        message = {"type": message_type, "body": body}
    elif message_type == 6:
        message = {'type': message_type, 'command': body}
    elif message_type == 7:
        message = {'type': message_type, 'input': body}
    return json.dumps(message)
"""

def create_msg(msg_type, ip=None, backup_store_time=None, command=None):
    if msg_type == 1:
        # Discover message
        curr_dt = datetime.now()
        timestamp = int(round(curr_dt.timestamp()))
        return json.dumps({'type': msg_type, 'IP': ip, 'ID': timestamp})
    elif msg_type == 2:
        # Discover response
        return json.dumps({'type': msg_type, 'IP': ip})
    elif msg_type == 3:
        # Initialize app
        return json.dumps({'type': msg_type, 'backup_store_time': backup_store_time})
    elif msg_type == 4:
        pass
    elif msg_type == 5:
        pass
    elif msg_type == 6:
        return json.dumps({'type': msg_type, 'command': command})
    elif msg_type == 7:
        return json.dumps({'type': msg_type, 'input': command})
    else:
        raise Exception('Wrong type of msg')


def discover_online_devices():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("", 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        msg = create_msg(1, ip=ip_address)
        #print(msg)
        for i in range(10):
            sock.sendto(msg.encode(encoding=encoding), ('<broadcast>', port))


def send_msg(host, msg):
    byte_msg = msg.encode('utf-8')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(byte_msg)


def listen_discover_message():
    global user_ip

    receivedFile = {}
    lastPackage = False
    lastPackageSEQ = 0
    
    IDs = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("", port))
        s.setblocking(False)
        while True:
            result = select.select([s], [], [])
            json_msg = result[0][0].recv(10240)
            message = json.loads(json_msg.decode(encoding=encoding))
            if message["type"] == 1:
                if message["IP"] != ip_address:

                    if message['ID'] in IDs:
                        continue
                    IDs.append(message['ID'])

                    user_ip = message['IP']
                    discover_response = create_msg(2, ip_address)
                    send_msg(user_ip, discover_response)
                    
                    print(f'Connected to user with ip: {user_ip}')

            elif message["type"] == 4:
                fileName = message["name"]
                fileName = fileName.encode(encoding)
                fileName = base64.b64decode(fileName)
                fileName = fileName.decode(encoding)
                packageSEQ = message["seq"]
                packageBody = message["body"]
                receivedFile[packageSEQ] = packageBody
                if packageBody == '':
                    lastPackage = True
                    lastPackageSEQ = packageSEQ
                respond_message = {"type": 5, "seq": packageSEQ, "rwnd": 10}
                respond_message = json.dumps(respond_message)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as new_socket:
                    new_socket.connect((message["IP"], port))
                    new_socket.sendall(respond_message.encode(encoding=encoding))
                    print('.', end='', flush=True)
                if lastPackage and (lastPackageSEQ + 1 == len(receivedFile)):
                    decodeFile(receivedFile, fileName)
                    print(f'\n{fileName} is finished downloading')
                    receivedFile.clear()
                    lastPackage = False
                    lastPackageSEQ = 0


def decodeFile(receivedFile, fileName):
    global server_ip

    endString = ''
    for elm in range(len(receivedFile)):
        endString += str(receivedFile[elm])
    if server_ip == "":
        save_path = './serverBackups'
        if not os.path.exists('./serverBackups'):
            os.makedirs('serverBackups')
    else:
        save_path = './downloads'
        if not os.path.exists('./downloads'):
            os.makedirs('downloads')
        fileName = fileName.split("/")[-1]

    completeName = os.path.join(save_path, fileName)
    with open(completeName, "wb") as imageFile:
        endString = endString.encode(encoding)
        decodedString = base64.decodebytes(endString)
        imageFile.write(decodedString)


def getFileArray(filename):
    with open(filename, "rb") as imageFile:
        b64String = base64.b64encode(imageFile.read())
    b64String = b64String.decode(encoding)

    packageNum = int(len(b64String) / packageSize) + 1
    fileArray = []

    for i in range(packageNum - 1):
        fileArray.append(b64String[i * packageSize:(i + 1) * packageSize])
    fileArray.append(b64String[(packageNum - 1) * packageSize:len(b64String)])
    fileArray.append('')
    return fileArray


def listen_message():
    global flyingPackages, receiveWindow, ackPackages, server_ip, user_ip

    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", port))
        s.listen()
        while True:
            conn, address = s.accept()
            with conn:
                output = conn.recv(10240)
                if output == "" or output is None:
                    print("There is a problem about your socket you should restart your cmd or computer")
                    break
                response = json.loads(output.decode(encoding=encoding))
                #print(response)
                if response["type"] == 1:
                    print('MESSAGE TYPE 1 NOT USED IN TCP')
                    continue
                elif response["type"] == 2:
                    server_ip = response['IP']
                    print(f'Connected to server with ip: {server_ip}')
                elif response["type"] == 3:
                    print('Initializing server...')
                    config = configparser.ConfigParser()
                    if os.path.exists('server_config.ini'):
                        config.read('server_config.ini')
                    config['SERVER'] = {'backup_store_time': response['backup_store_time']}
                    with open('server_config.ini', 'w') as f:
                        config.write(f)
                elif response["type"] == 5:
                    print('.', end='', flush=True)
                    currentReceiveWindow = response['rwnd']
                    ackSEQ = response['seq']
                    receiveWindow = currentReceiveWindow
                    ackPackages.append(ackSEQ)
                elif response['type'] == 6:
                    if response['command'] == "show":
                        send_directory_info()
                    else:
                        #print(f"Sending {response['command']}")
                        #print(user_ip)
                        sendFile_thread = Thread(target=sendFile, daemon=True, args=(response['command'], user_ip,))
                        sendFile_thread.start()
                elif response['type'] == 7:
                    #print("type 7 works")
                    print(response['input'])


def sendFile(fileName, user_ip):
    file_path = './serverBackups'
    completeName = os.path.join(file_path, fileName)
    fileSender(completeName, user_ip)


def send_directory_info():
    output = ""
    for root, dirs, files in os.walk("./serverBackups"):
        for f in files:
            output += (f + "\t" + str(os.stat("./serverBackups/" + f).st_size) + " bytes\n")
    msg = create_msg(7,command=output)
    send_msg(user_ip,msg)


def fileSender(fileName, receiver):
    global flyingPackages
    global receiveWindow
    global ackPackages
    packageCounter = 0
    fileArray = getFileArray(fileName)
    dt = datetime.now()
    dt.microsecond
    starting_time = int(round(dt.timestamp()))
    while (True):
        dti = datetime.now()
        dti.microsecond
        curr_time = int(round(dti.timestamp()))
        for elm in flyingPackages:
            if curr_time - flyingPackages[elm] >= 2:
                #print(f"{elm} : {curr_time - flyingPackages[elm]}")
                currentPackage = fileArray[elm]
                sendPackage(currentPackage, elm, fileName, receiver)
                flyingPackages[elm] = curr_time
        for elm in ackPackages:
            if elm in flyingPackages:
                del flyingPackages[elm]
        if (len(flyingPackages) < receiveWindow):
            if packageCounter < len(fileArray):
                currentPackage = fileArray[packageCounter]
                sendPackage(currentPackage, packageCounter, fileName, receiver)
                flyingPackages[packageCounter] = curr_time
                packageCounter += 1
            else:
                flyingPackages.clear()
                receiveWindow = 1
                ackPackages.clear()
                sleep(0.5)
                print('\nFile is sent successfully')
                return


def sendPackage(package, SEQ, fileName, receiver):
    fileName = fileName.encode(encoding)
    fileName = base64.b64encode(fileName)
    fileName = fileName.decode(encoding)
    message = {"type": 4, "name": fileName, "seq": SEQ, "body": package, "IP": ip_address}
    jsonMessage = json.dumps(message)
    opened_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    opened_socket.sendto(jsonMessage.encode(encoding=encoding), (receiver, port))

def get_all_file_paths(directory):
  
    # initializing empty file paths list
    file_paths = []
  
    # crawling through directory and subdirectories
    for root, directories, files in os.walk(directory):
        for filename in files:
            # join the two strings in order to form the full filepath.
            filepath = os.path.join(root, filename)
            file_paths.append(filepath)
  
    # returning all file paths
    return file_paths


def backup_files(backup_dir):
    zip_name = datetime.now().strftime("%Y-%m-%d_%H:%M:%S") + '.zip'
    file_paths = get_all_file_paths(backup_dir)
    
    # printing the list of all files to be zipped
    print('Following files will be backed up:')
    for file_name in file_paths:
        print(file_name)

    # writing files to a zipfile
    with ZipFile(zip_name, 'w') as zip:
        # writing each file one by one
        for file in file_paths:
            zip.write(file)

    print('Starting backup')
    
    sendFile_thread = Thread(target=fileSender, daemon=True, args=(zip_name, server_ip,))
    sendFile_thread.start()
    sendFile_thread.join()

    os.remove(zip_name)

def check_ssid(saved_ssid, path_to_backup_folder):
    global wifi_ssid, server_ip, system_type

    while True:
        sleep(5)
        current_ssid = get_ssid(system_type)
        #print(saved_ssid, current_ssid, wifi_ssid)
        if current_ssid == wifi_ssid:
            # Still on the same network
            continue
        print('Network change detected')
        wifi_ssid = current_ssid
        if current_ssid != saved_ssid:
            # Current network is different than home saved network
            server_ip = ""
            continue
        
        sleep(10)
        discover_online_devices()
        sleep(1)
        print(server_ip)
        if server_ip == "":
            continue
        print('Backing up folders...')
        backup_files(path_to_backup_folder)

        


def get_ssid(system_type):
    if system_type == 'Darwin':
        ssid_line = r"/Sy*/L*/Priv*/Apple8*/V*/C*/R*/airport -I | awk '/ SSID:/ {print $2}'"
    elif system_type == 'Linux':
        ssid_line = 'iwgetid -r'
    elif system_type == 'Windows':
        # TODO: Add windows command
        raise NotImplementedError('Windows not supported')
    else:
        raise NotImplementedError('Platform not supported')

    return subprocess.run(ssid_line, shell=True, capture_output=True, text=True).stdout.strip()

def run_user():
    listen_thread = Thread(target=listen_message, daemon=True)
    discover_listen_thread = Thread(target=listen_discover_message, daemon=True)
    listen_thread.start()
    discover_listen_thread.start()
    discover_online_devices()

    config = configparser.ConfigParser()
    if os.path.exists('user_config.ini'):
        config.read('user_config.ini')
    else:
        # First time configure
        print('Initializing first time setup')
        sleep(1)
        if input(f'Do you want to connect server with ip {server_ip} on wifi with ssid {wifi_ssid}? (y/n): ') == 'y':
            max_time_days = int(input('What is the maximum amount of days should backups be stored on backup server? '))
            path_to_backup_folder = input('Which folder do you want to backup (path)? ')
            config['USER'] = {'backup_store_time': max_time_days, 'server_ip': server_ip, 'path_to_backup_folder': path_to_backup_folder, 'saved_ssid': wifi_ssid}
            with open('user_config.ini', 'w') as f:
                config.write(f)
            init_msg = create_msg(3, backup_store_time=max_time_days)
            send_msg(server_ip, init_msg)
        else:
            return

    # Detect network changes
    network_changes_thread = Thread(target=check_ssid, daemon=True, args=(config['USER']['saved_ssid'], config['USER']['path_to_backup_folder']))
    network_changes_thread.start()
        
    while True:

        user_input = input()
        if user_input == "backup":
            backup_files(config['USER']['path_to_backup_folder'])
        elif user_input == 'show':
            msg = create_msg(6, command = "show")
            send_msg(server_ip, msg)

        
        elif user_input.split()[0] == "get":
            fileName = user_input.split()[1]
            print('Downloading', fileName)
            msg = create_msg(6, command=fileName)
            send_msg(server_ip, msg)

        
        else:
            print("No Valid Command")

        sleep(0.3)

    
    listen_thread.join()
    discover_listen_thread.join()

def run_server():
    listen_thread = Thread(target=listen_message, daemon=True)
    discover_listen_thread = Thread(target=listen_discover_message, daemon=True)
    listen_thread.start()
    discover_listen_thread.start()
    print('Waiting for user connection')
    listen_thread.join()
    discover_listen_thread.join()

def main():
    global system_type, wifi_ssid

    get_ip()
    print('Local ip:', ip_address)

    system_type = platform.system()
    wifi_ssid = get_ssid(system_type)

    print('wifi ssid:', wifi_ssid)

    machine = input('Which machine is this?: (0: User, 1: Server) ')
    if machine == '0':
        run_user()
    elif machine == '1':
        run_server()
    else:
        raise ValueError('Wrong input')

if __name__ == '__main__':
    main()