#!/usr/bin/env python

import nmap
import optparse
import socket
from threading import Thread, Semaphore
import sys


display_semaphore = Semaphore(1)

def hostToIP(tgtHost):

    ip_address = socket.gethostbyname(tgtHost)

    return ip_address


def nmapScan(tgtHost, tgtPort):

    nmap_scanner = nmap.PortScanner()

    tgtHost = hostToIP(tgtHost)

    try:
        nmap_scanner.scan(hosts=tgtHost, ports=tgtPort, arguments='-sT')
        state=nmap_scanner[tgtHost]['tcp'][int(tgtPort)]['state']

        display_semaphore.acquire()
        print "[*] %s/tcp - %s" % (tgtPort, state)

    except KeyError:
        display_semaphore.acquire()
        print "[-] Unable to scan %s" % tgtHost
    except:
        display_semaphore.acquire()
        print "[-] Unexpected error: %s" % sys.exc_info()[0]
    finally:
        display_semaphore.release()


def main():

    usage = 'usage %prog -H <target host> -p <target ports>'

    parser = optparse.OptionParser( usage )

    parser.add_option( '-H', dest = 'tgtHost',  type = 'string', help = 'specify the target host' )
    parser.add_option( '-p', dest = 'tgtPorts', type = 'string', help = 'specify the target ports - comma delmited, no spaces' )

    ( options, args ) = parser.parse_args()

    if options.tgtHost == None or options.tgtPorts == None:
        print
        parser.print_help()
        print
        exit(0)

    tgtHost = options.tgtHost
    tgtPorts = options.tgtPorts.split(',')

    print "Port scan report for: %s" % tgtHost
    for tgtPort in tgtPorts:
        t = Thread( target=nmapScan, args = ( tgtHost, tgtPort ) )
        t.run()

if __name__ == '__main__':
    main()
