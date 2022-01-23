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

ip_address = ""
my_name = ""
port = 12345
ip_dictionary = {}
discover_response_dictionary = {}
encoding = "utf-8"
flyingPackages = {}
receiveWindow = 1
packageSize = 1500
ackPackages = []

system_type = ""

def get_ip():
    global ip_address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
    finally:
        s.close()


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
    return json.dumps(message)


def discover_online_devices():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("", 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for i in range(10):
            sock.sendto(create_message(1).encode(encoding=encoding), ('<broadcast>', port))


def show_online_devices():
    global ip_dictionary
    if len(ip_dictionary) == 0:
        print("There is no active user")
    else:
        print("Active Users:")
        for key in ip_dictionary.keys():
            print(key)


def listen_discover_message():
    receivedFile = {}
    lastPackage = False
    lastPackageSEQ = 0
    global ip_dictionary
    global discover_response_dictionary
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("", port))
        s.setblocking(False)
        while True:
            result = select.select([s], [], [])
            json_msg = result[0][0].recv(10240)
            message = json.loads(json_msg.decode(encoding=encoding))
            if message["type"] == 1:
                if message["IP"] != ip_address:
                    if not message["name"] in discover_response_dictionary.keys():
                        ip_dictionary[message["name"]] = message["IP"]
                        discover_response_dictionary[message["name"]] = message["ID"]
                        respond_message = create_message(2)
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as new_socket:
                            new_socket.connect((message["IP"], port))
                            new_socket.sendall(respond_message.encode(encoding=encoding))
                    elif message["name"] in discover_response_dictionary.keys() and discover_response_dictionary[
                        message["name"]] != message["ID"]:
                        print(message["name"], "has changed id. Old ID: ",
                              discover_response_dictionary[message["name"]], 'new ID:', message["ID"])
                        ip_dictionary[message["name"]] = message["IP"]
                        discover_response_dictionary[message["name"]] = message["ID"]
                        respond_message = create_message(2)
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as new_socket:
                            new_socket.connect((message["IP"], port))
                            new_socket.sendall(respond_message.encode(encoding=encoding))
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
                if lastPackage and (lastPackageSEQ + 1 == len(receivedFile)):
                    decodeFile(receivedFile, fileName)
                    print(f'{fileName} packageNo {packageSEQ} is received')
                    receivedFile.clear()
                    lastPackage = False
                    lastPackageSEQ = 0


def decodeFile(receivedFile, fileName):
    endString = ''
    for elm in range(len(receivedFile)):
        endString += str(receivedFile[elm])

    with open(fileName, "wb") as imageFile:
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
    global ip_dictionary
    global flyingPackages
    global receiveWindow
    global ackPackages
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
                if response["type"] == 1:
                    if response["IP"] != ip_address:
                        ip_dictionary[response["name"]] = response["IP"]
                    respond_message = create_message(2)
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as new_socket:
                        new_socket.connect((response["IP"], port))
                        new_socket.sendall(respond_message.encode(encoding=encoding))
                elif response["type"] == 2:
                    if response["IP"] != ip_address:
                        ip_dictionary[response["name"]] = response["IP"]
                elif response["type"] == 3:
                    print(response["name"] + ":   " + response["body"])
                elif response["type"] == 5:
                    currentReceiveWindow = response['rwnd']
                    ackSEQ = response['seq']
                    receiveWindow = currentReceiveWindow

                    ackPackages.append(ackSEQ)


def application_user_interface():
    global ip_dictionary
    while True:

        user_input = input()
        if user_input == "list":
            show_online_devices()
        elif user_input.split()[0] == "send":
            receiver = user_input.split()[1]
            if receiver in ip_dictionary.keys():
                receiver_ip = ip_dictionary.get(receiver)
                chat_message = " ".join(user_input.split()[2:])
                json_message = create_message(3, body=chat_message)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    try:
                        s.connect((receiver_ip, port))
                        s.sendall(json_message.encode(encoding=encoding))
                    except socket.error:
                        print("message cannot be sent! " + receiver + " is offline!")
                        ip_dictionary.pop(receiver)
            else:
                print("No Such Active User!")
        elif user_input.split()[0] == "sendFile":
            receiver = user_input.split()[1]
            if receiver in ip_dictionary.keys():
                receiver_ip = ip_dictionary.get(receiver)
                filename = user_input.split()[2]
                sendFile_thread = Thread(target=fileSender, daemon=True, args=(filename, receiver_ip,))
                sendFile_thread.start()
            else:
                print("No Such Active User!")
        else:
            print("No Valid Command")

        sleep(0.3)


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
    message = {"type": 4, "name": fileName, "seq": SEQ, "body": package, "IP": ip_address}
    jsonMessage = json.dumps(message)
    opened_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    opened_socket.sendto(jsonMessage.encode(encoding=encoding), (receiver, port))


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

    while True:

        user_input = input()
        if user_input == "list":
            show_online_devices()
        elif user_input.split()[0] == "send":
            receiver = user_input.split()[1]
            if receiver in ip_dictionary.keys():
                receiver_ip = ip_dictionary.get(receiver)
                chat_message = " ".join(user_input.split()[2:])
                json_message = create_message(3, body=chat_message)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    try:
                        s.connect((receiver_ip, port))
                        s.sendall(json_message.encode(encoding=encoding))
                    except socket.error:
                        print("message cannot be sent! " + receiver + " is offline!")
                        ip_dictionary.pop(receiver)
            else:
                print("No Such Active User!")
        elif user_input.split()[0] == "sendFile":
            receiver = user_input.split()[1]
            if receiver in ip_dictionary.keys():
                receiver_ip = ip_dictionary.get(receiver)
                filename = user_input.split()[2]
                sendFile_thread = Thread(target=fileSender, daemon=True, args=(filename, receiver_ip,))
                sendFile_thread.start()
            else:
                print("No Such Active User!")
        else:
            print("No Valid Command")

        sleep(0.3)

    discover_online_devices()
    listen_thread.join()
    discover_listen_thread.join()

def run_server():
    application_ui_thread = Thread(target=application_user_interface)
    listen_thread = Thread(target=listen_message, daemon=True)
    discover_listen_thread = Thread(target=listen_discover_message, daemon=True)
    listen_thread.start()
    discover_listen_thread.start()
    application_ui_thread.start()
    listen_thread.join()
    discover_listen_thread.join()
    application_ui_thread.join()

def main():
    global system_type

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