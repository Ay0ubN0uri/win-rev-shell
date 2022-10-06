import re
import sys


regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

def isValidIp(ip):
    return re.search(regex, ip) is not None

def printUsage():
    print("Error\nUsage : ip2hex.py ip_address")
    
if __name__=="__main__":
    if len(sys.argv)==2:
        ip = sys.argv[1]
        if isValidIp(ip):
            hex_res = ''
            for num in ip.split('.'):
                hex_res += '0x%02x,' % int(int(num)^0xaa)
            print('result xored with 0xaa : ',hex_res[:-1])
        else:
            printUsage()
    else:
        printUsage()