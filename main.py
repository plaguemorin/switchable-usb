#!/usr/bin/env python3
# inspiration from http://starin.info/Product%20Info/Icron%20Technologies/Manuals/White%20Paper%20-%20Switchable%20USB%20Device%20Configuration%20Network%20Protocol.pdf
# https://usermanual.wiki/Document/WhitePaperSwitchableUSBDeviceConfigurationNetworkProtocol.1399928265.pdf
# 90-01032-A04 Icron_SwitchableUSB_Device_Configuration_Network_Protocol.docx
# Just note that Crestron has different magic

import socket
import macaddress
import sys
import time

PORT = 6137
MAGIC_NUMBER_STR = b"\xA9\xC4\xD8\xF4"
MAC_ADDRESS_MANUFACTURER = b"\x00\x1B\x13"
ADDRESS = "255.255.255.255"

LEX = 0
REX = 1
DMUSB_REQUEST_DEVICE_INFORMATION = 0
DMUSB_REPLY_DEVICE_INFORMATION = 1
DMUSB_PING = 2
DMUSB_ACKNOWLEDGE = 3
DMUSB_PAIR = 4
DMUSB_REMOVE_PAIRING = 5
DMUSB_REQUEST_DEVICE_TOPOLOGY = 6
DMUSB_REPLY_DEVICE_TOPOLOGY = 7
DMUSB_REPLY_UNHANDLED_COMMAND = 8
DMUSB_NEGATIVE_ACKNOWLEDGE = 9
DMUSB_REMOVE_ALL_PAIRINGS = 10

transaction = 0
usbUdpSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def device_type_name(t: bytes) -> str:
    if t == LEX:
        return 'LEX'
    elif t == REX:
        return 'REX'
    return 'UNK'


def parseDeviceAddress(address: str) -> bytes:
    mac = macaddress.parse(address, macaddress.EUI48)
    return bytes(mac)


def sendCommand(command):
    global transaction, usbUdpSock

    transaction = transaction + 1

    tx_number = bytes([
        (transaction & 0xFF000000) >> 24,
        (transaction & 0x00FF0000) >> 16,
        (transaction & 0x0000FF00) >> 8,
        transaction & 0x000000FF
    ])

    msg = MAGIC_NUMBER_STR + tx_number + command

    usbUdpSock.sendto(msg, (ADDRESS, PORT))

    return transaction


def parse(data: bytes):
    if not data.startswith(MAGIC_NUMBER_STR):
        return 0, 0, 0, 0

    # data_magic = data[0:len(MAGIC_NUMBER_STR)]
    tx_number = (data[len(MAGIC_NUMBER_STR) + 0] << 24) + (data[len(MAGIC_NUMBER_STR) + 1] << 16) + (data[len(MAGIC_NUMBER_STR) + 2] << 8) + (
        data[len(MAGIC_NUMBER_STR) + 3])
    command = data[len(MAGIC_NUMBER_STR) + 4]
    from_device = bytes(6)
    extra = bytes([0])
    try:
        from_device = data[len(MAGIC_NUMBER_STR) + 5:len(MAGIC_NUMBER_STR) + 11]
        extra = data[len(MAGIC_NUMBER_STR) + 11:]
    except IndexError:
        pass

    return tx_number, command, from_device, extra


def sendPing(device0Address: str):
    return sendCommand(bytes([DMUSB_PING]) + parseDeviceAddress(device0Address))


def sendInfoRequest(device0Address: str):
    return sendCommand(bytes([DMUSB_REQUEST_DEVICE_INFORMATION]) + parseDeviceAddress(device0Address))


def sendDeviceTopologyRequest(device0Address: str):
    return sendCommand(bytes([DMUSB_REQUEST_DEVICE_TOPOLOGY]) + parseDeviceAddress(device0Address))


def sendRemoveAllPairing(device0Address: str):
    return sendCommand(bytes([DMUSB_REMOVE_ALL_PAIRINGS]) + parseDeviceAddress(device0Address))


def sendPair(device0Address: str, device1Address: str):
    return sendCommand(bytes([DMUSB_PAIR]) + parseDeviceAddress(device0Address) + parseDeviceAddress(device1Address))


def sendFind():
    return sendCommand(bytes([0]) + b"\xFF\xFF\xFF\xFF\xFF\xFF")

def sendDhcpRequest(device0Address: str):
    return sendCommand(bytes([]) + parseDeviceAddress(device0Address))

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    #interfaces = socket.getaddrinfo(host=socket.gethostname(), port=None, family=socket.AF_INET)
    #allips = [ip[-1][0] for ip in interfaces]

    usbUdpSock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    usbUdpSock.setblocking(False)
    usbUdpSock.settimeout(5.0)
    usbUdpSock.bind(("0.0.0.0", PORT))

    socket_address = usbUdpSock.getsockname()
    print("Asynchronous socket server launched on socket: %s" % str(socket_address))

    if len(sys.argv) < 2:
        print("Expected command: %s [discover|pair|clearpairing|info|topo]" % sys.argv[0])
        sys.exit(-1)

    clicmd = sys.argv[1]
    if clicmd == 'discover':
        sendFind()
    elif clicmd == 'pair':
        if len(sys.argv) != 4:
            print("Expected command: %s pair [device1Mac] [device2Mac]" % sys.argv[0])
            sys.exit(-1)
        device0Specified = sys.argv[2]
        device1Specified = sys.argv[3]
        sendRemoveAllPairing(device0Specified)
        sendRemoveAllPairing(device1Specified)

        time.sleep(1)

        sendPair(device0Specified, device1Specified)
        sendPair(device1Specified, device0Specified)
    elif clicmd == 'info':
        if len(sys.argv) != 3:
            print("Expected command: %s info [deviceMac]" % sys.argv[0])
            sys.exit(-1)
        sendInfoRequest(sys.argv[2])
    elif clicmd == 'clearpairing':
        if len(sys.argv) != 3:
            print("Expected command: %s clearpairing [deviceMac]" % sys.argv[0])
            sys.exit(-1)
        device0Specified = sys.argv[2]
        sendRemoveAllPairing(device0Specified)
    elif clicmd == 'topo':
        if len(sys.argv) != 3:
            print("Expected command: %s topo [deviceMac]" % sys.argv[0])
            sys.exit(-1)
        device0Specified = sys.argv[2]
        sendDeviceTopologyRequest(device0Specified)
    elif clicmd == 'dhcp':
        if len(sys.argv) != 3:
            print("Expected command: %s dhcp [deviceMac]" % sys.argv[0])
            sys.exit(-1)
        device0Specified = sys.argv[2]
        sendDhcpRequest(device0Specified)
    else:
        print("wrong command")
        print("Expected command: %s [discover|pair|info]" % sys.argv[0])
        sys.exit(-1)

    while True:
        try:
            data, addr = usbUdpSock.recvfrom(1024)
        except TimeoutError:
            sys.exit(0)

        if addr[1] == PORT:
            tx_num, cmd, device, extra = parse(data)
            if cmd == DMUSB_REQUEST_DEVICE_INFORMATION:
                print("Request information TX: %d, MAC: %s" % (tx_num, device.hex()))
            elif cmd == DMUSB_REPLY_DEVICE_INFORMATION:
                info_a = extra[0:32]
                info_b = extra[32:64]
                version = extra[64:64 + 12]
                paired_to = extra[-6:]
                device_type = extra[-8]

                print("Device %s is a %s (in reply to %d) information: paired to %s, %s" % (
                    device.hex(),
                    device_type_name(device_type),
                    tx_num,
                    ':'.join('{:02x}'.format(x) for x in paired_to),
                    extra))
            elif cmd == DMUSB_PING:
                print("PING TX: %d, MAC: %s" % (tx_num, device.hex()))
            elif cmd == DMUSB_ACKNOWLEDGE:
                print("Device %s has ACK message %d (%s)" % (device.hex(), tx_num, extra))
            elif cmd == DMUSB_PAIR:
                print("Pairing request to device %s, TX: %d, %s" % (device.hex(), tx_num, extra))
            elif cmd == DMUSB_REMOVE_PAIRING:
                print("Remove pairing to device %s, TX: %d, %s" % (device.hex(), tx_num, extra))
            elif cmd == DMUSB_REQUEST_DEVICE_TOPOLOGY:
                print("Request device topology to %s, TX: %d, %s" % (device.hex(), tx_num, extra))
            elif cmd == DMUSB_REPLY_DEVICE_TOPOLOGY:
                print("Device %s (reply to %d) has topology: %s" % (device.hex(), tx_num, extra))
            elif cmd == DMUSB_REPLY_UNHANDLED_COMMAND:
                print("Device %s replied unhandled command (reply to %d): %s" % (device.hex(), tx_num, extra))
            elif cmd == DMUSB_NEGATIVE_ACKNOWLEDGE:
                print("Device %s has NACK message %d (%s)" % (device.hex(), tx_num, extra))
            elif cmd == DMUSB_REMOVE_ALL_PAIRINGS:
                print("Remove all pairing in device %s, TX: %d, %s" % (device.hex(), tx_num, extra))
            else:
                print("Unknown data! DEVICE: %s, TX: %d, CMD: %d, %s" % (device.hex(), tx_num, cmd, extra))
