from cgitb import text
from http import server
import socket
import json
from datetime import datetime
import sys
from threading import Thread
from time import sleep
from unittest.mock import NonCallableMock
import select
import subprocess
import platform
import os
import configparser
from venv import create
from zipfile import ZipFile
### Added libraries
import base64

threads = []
local_ip = 0
user_ip = 0
server_ip = 0
wifi_ssid = ''
system_type = ''

### added variables
flyingPackages = {}
receiveWindow = 1
packageSize = 1500
ackPackages = []
port = 1453  ## can be changed
encoding = "utf-8"


threads = []
local_ip = 0
user_ip = 0
server_ip = 0
wifi_ssid = ''
system_type = ''

def decodeFile(receivedFile, fileName):
    endString = ''
    for elm in range(len(receivedFile)):
        endString += str(receivedFile[elm])

    save_path = './serverBackups'

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
                print(f"{elm} : {curr_time - flyingPackages[elm]}")
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
                print('file is sent successfully')
                return


def sendPackage(package, SEQ, fileName, receiver):
    fileName = fileName.encode(encoding)
    fileName = base64.b64encode(fileName)
    fileName = fileName.decode(encoding)
    message = {"type": 4, "name": fileName, "seq": SEQ, "body": package, "IP": local_ip}
    jsonMessage = json.dumps(message)
    opened_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    opened_socket.sendto(jsonMessage.encode(encoding=encoding), (receiver, port))




def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def tcp_listener(local_ip):
    global server_ip

    HOST = ''
    PORT = 1453
    while True:
        try:
            incoming = {}
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((HOST, PORT))
                s.listen()
                conn, addr = s.accept()
                with conn:
                    data = conn.recv(10240)
                    incoming = json.loads(data.decode('utf-8'))
                    
            if incoming['type'] == 1:
                print('MESSAGE TYPE 1 NOT USED IN TCP')
                continue
            elif incoming['type'] == 2:
                server_ip = incoming['IP']
                print(f'Connected to server with ip: {server_ip}')
            elif incoming['type'] == 3:
                print('Initializing server...')
                config = configparser.ConfigParser()
                if os.path.exists('server_config.ini'):
                    config.read('server_config.ini')
                config['SERVER'] = {'backup_store_time': incoming['backup_store_time']}
                with open('server_config.ini', 'w') as f:
                    config.write(f)
            elif incoming['type'] == 5:
                currentReceiveWindow = incoming['rwnd']
                ackSEQ = incoming['seq']
                receiveWindow = currentReceiveWindow
                ackPackages.append(ackSEQ)
            elif incoming['type'] == 6:
                send_directory_info()
            elif incoming['type'] == 7:
                print(incoming['input'])


        except:
            continue

def send_directory_info():
    filenames = next(os.walk("./serverBackups"), (None, None, []))[2]
    msg = create_msg(7,command=filenames)
    send_msg(user_ip,msg)

def udp_listener(local_ip):

    receivedFile = {}       ####
    lastPackage = False     ####
    lastPackageSEQ = 0      ####

    HOST = ''
    PORT = 1453
    bufferSize = 10240
    IDs = []
    while True:
        incoming = {}
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind((HOST, PORT))
            s.setblocking(0)
            result = select.select([s], [], [])
            data = result[0][0].recv(bufferSize)
            incoming = json.loads(data.decode('utf-8'))

            if incoming["type"] == 1:  ####
                print(incoming)

                if incoming['ID'] in IDs:
                    continue
                IDs.append(incoming['ID'])

                user_ip = incoming['IP']
                print(user_ip)
                discover_response = create_msg(2, local_ip)
                send_msg(user_ip, discover_response)
                
                print(f'Connected to user with ip: {user_ip}')

            elif incoming["type"] == 4:  ####
                fileName = incoming["name"]
                fileName = fileName.encode(encoding)
                fileName = base64.b64decode(fileName)
                fileName = fileName.decode(encoding)
                packageSEQ = incoming["seq"]
                packageBody = incoming["body"]
                receivedFile[packageSEQ] = packageBody
                if packageBody == '':
                    lastPackage = True
                    lastPackageSEQ = packageSEQ
                respond_message = {"type": 5, "seq": packageSEQ, "rwnd": 10}
                respond_message = json.dumps(respond_message)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as new_socket:
                    new_socket.connect((incoming["IP"], port))
                    new_socket.sendall(respond_message.encode(encoding=encoding))
                if lastPackage and (lastPackageSEQ + 1 == len(receivedFile)):
                    decodeFile(receivedFile, fileName)
                    print(f'{fileName} packageNo {packageSEQ} is received')
                    receivedFile.clear()
                    lastPackage = False
                    lastPackageSEQ = 0

def create_msg(msg_type, ip=None, ID=None, backup_store_time=None, command=None):
    if msg_type == 1:
        # Discover message
        return {'type': msg_type, 'IP': ip, 'ID': ID}
    elif msg_type == 2:
        # Discover response
        return {'type': msg_type, 'IP': ip}
    elif msg_type == 3:
        # Initialize app
        return {'type': msg_type, 'backup_store_time': backup_store_time}
    elif msg_type == 4:
        pass
    elif msg_type == 5:
        pass
    elif msg_type == 6:
        return {'type': msg_type, 'command': command}
    elif msg_type == 7:
        return {'type': msg_type, 'input': command}
    else:
        raise Exception('Wrong type of msg')


def send_msg(host, msg):

    HOST = host
    PORT = 1453

    byte_msg = json.dumps(msg).encode('utf-8')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(byte_msg)


def bcast_discovery(msg):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        msg = json.dumps(msg).encode('utf-8')
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(msg, ('<broadcast>', 1453))

def send_greeting(target, discover_msg, address_book):
    try:
        send_msg(target, discover_msg)
        # print('Sent discovery to ' + target)
        HOST = ''
        PORT = 1453
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            conn, addr = s.accept()
            with conn:
                data = conn.recv(10240)
                data = json.loads(data.decode('utf-8'))
                address_book[data['name']] = data['IP']
    except:
        return

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
    print('Following files will be zipped:')
    for file_name in file_paths:
        print(file_name)

    # writing files to a zipfile
    with ZipFile(zip_name, 'w') as zip:
        # writing each file one by one
        for file in file_paths:
            zip.write(file)

    print('All files zipped successfully!')        
    
    sendFile_thread = Thread(target=fileSender, daemon=True, args=(zip_name, server_ip,))
    sendFile_thread.start()
    sendFile_thread.join()
    os.remove(zip_name)


def run_user():
    print(local_ip)
    
    tcp_listener_t = Thread(target=tcp_listener, args=(local_ip,))
    tcp_listener_t.daemon = True
    tcp_listener_t.start()
    threads.append(tcp_listener_t)
    epoch = int(datetime.now().timestamp())
    discover = create_msg(1, ip=local_ip, ID=epoch)
    for i in range(10):
        try:
            bcast_discovery(discover)
        except:
            pass

    config = configparser.ConfigParser()
    if os.path.exists('user_config.ini'):
        config.read('user_config.ini')
    else:
        # First time configure
        print('Initializing first time setup')
        sleep(1)
        if input(f'Do you want to connect server with ip {server_ip} on wifi with ssid {wifi_ssid}? (y/n): ') == 'y':
            max_time_days = int(input('What is the maximum amount of days should backups be stored on backup server? '))
            config['USER'] = {'backup_store_time': max_time_days, 'server_ip': server_ip}
            with open('user_config.ini', 'w') as f:
                config.write(f)
            init_msg = create_msg(3, backup_store_time=max_time_days)
            send_msg(server_ip, init_msg)
        else:
            return

    while True:
        inp = input()
        if inp == 'backup':
            backup_files('./backup/')
        elif inp == 'show':
            msg= create_msg(6, command = "show")
            send_msg(server_ip, msg)

            
        
    


def run_server():
    tcp_listener_t = Thread(target=tcp_listener, args=(local_ip,))
    tcp_listener_t.daemon = True
    tcp_listener_t.start()
    threads.append(tcp_listener_t)
    print('Waiting for user connection')
    udp_listener_t = Thread(target=udp_listener, args=(local_ip,))
    udp_listener_t.daemon = True
    udp_listener_t.start()
    
    
    
    threads.append(udp_listener_t)
    #udp_listener_t.join()


def main():

    global local_ip, server_ip, wifi_ssid, system_type

    local_ip = get_ip()
    print('Local ip: ' + local_ip)

    system_type = platform.system()
    if system_type == 'Darwin':
        wifi_ssid = subprocess.run(r"/Sy*/L*/Priv*/Apple8*/V*/C*/R*/airport -I | awk '/ SSID:/ {print $2}'", shell=True, capture_output=True, text=True).stdout.strip()
    elif system_type == 'Linux':
        wifi_ssid = subprocess.run('iwgetid -r', shell=True, capture_output=True, text=True).stdout.strip()
    elif system_type == 'Windows':
        # TODO: Add windows command
        pass
    else:
        raise NotImplementedError('Platform not supported')

    print('wifi ssid:', wifi_ssid)

    machine = input('Which machine is this?: (0: User, 1: Server) ')
    if machine == '0':
        run_user()
    elif machine == '1':
        run_server()
    else:
        raise ValueError('Wrong input')

    for t in threads:
        t.join()

    return
    
    hosts = []

    address_book = {}
    if start_tcp_listener:
        tcp_listener_t = Thread(target=tcp_listener, args=(username, local_ip, address_book))
        tcp_listener_t.daemon = True
        tcp_listener_t.start()



    epoch = int(datetime.now().timestamp())
    discover = create_msg(1, username, local_ip, ID=epoch)
    
   
    for i in range(10):
        try:
            bcast_discovery(discover)
        except:
            pass

    sleep(1)
    
    if start_udp_listener:
        udp_listener_t = Thread(target=udp_listener, args=(username, local_ip, address_book))
        udp_listener_t.daemon = True
        udp_listener_t.start()
    

    if address_book:
        print('Online users:')
        for u, uip in address_book.items():
            print(f'{u} ({uip})')
    else:
        print('No online users found')

    



    while True:
        cmd = input().split()
        if cmd[0] == 'quit':
            return
        elif cmd[0] == 'msg':
            target_name = cmd[1]
            body = ' '.join(cmd[2:])
            if body == '':
                print('cannot send empty message')
                continue
            try:
                target_ip = address_book[target_name]
            except KeyError:
                print(f'User {target_name} not found')
                continue

            chat = create_msg(3, username, body=body)
            try:
                send_msg(target_ip, chat)
            except:
                address_book.pop(cmd[1])
                print(f'User {target_name} has gone offline, message is not delivered')
                if address_book:
                    print('Online users:')
                    for u, uip in address_book.items():
                        print(f'{u} ({uip})')
                else:
                    print('No online users found')
                continue

            dt = str(datetime.now().strftime("%x %X"))
            print(f'[{dt}] {target_name} <-- {username}: {body}')

        elif cmd[0] == 'online':
            print(address_book)

        else:
            print('unknown command')



if __name__ == '__main__':
    main()

    ### to send file:
    ### sendFile_thread = Thread(target=fileSender, daemon=True, args=(filename, receiver_ip,))
    ### sendFile_thread.start()
