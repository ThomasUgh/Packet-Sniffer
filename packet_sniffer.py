#!/usr/bin/env python3

import socket
import struct
import textwrap
import sys
import argparse
import datetime
import re
import base64
from collections import defaultdict
import json

class PacketSniffer:
    def __init__(self, interface=None, output_file=None, filter_protocol=None, 
                 filter_port=None, filter_ip=None, verbose=False, extract_creds=True, show_hex=False):
        self.interface = interface
        self.output_file = output_file
        self.filter_protocol = filter_protocol
        self.filter_port = filter_port
        self.filter_ip = filter_ip
        self.verbose = verbose
        self.extract_creds = extract_creds
        self.show_hex = show_hex
        
        self.stats = defaultdict(int)
        self.packet_count = 0
        self.captured_credentials = []
        
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except PermissionError:
            print("[!] Error: This script requires root privileges!")
            print("[!] Run with: sudo python3 packet_sniffer.py")
            sys.exit(1)
        except AttributeError:
            print("[!] Error: AF_PACKET not available on this platform")
            print("[!] This tool requires Linux")
            sys.exit(1)
            
    def start_sniffing(self):
        print(f"[*] Starting packet capture...")
        print(f"[*] Interface: {self.interface or 'ALL'}")
        print(f"[*] Filters: Protocol={self.filter_protocol}, Port={self.filter_port}, IP={self.filter_ip}")
        print(f"[*] Press Ctrl+C to stop\n")
        
        try:
            while True:
                raw_data, addr = self.sock.recvfrom(65535)
                self.packet_count += 1
                self.process_packet(raw_data)
                
        except KeyboardInterrupt:
            print("\n\n[*] Stopping packet capture...")
            self.print_statistics()
            if self.captured_credentials:
                self.print_credentials()
            if self.output_file:
                self.save_results()
    
    def process_packet(self, data):
        eth_header = self.parse_ethernet(data)
        if not eth_header:
            return
            
        dest_mac, src_mac, eth_proto, payload = eth_header
        self.stats['ethernet'] += 1
        
        if eth_proto == 0x0800:
            ip_header = self.parse_ipv4(payload)
            if not ip_header:
                return
                
            version, header_length, ttl, proto, src_ip, dest_ip, ip_payload = ip_header
            
            if self.filter_ip and self.filter_ip not in [src_ip, dest_ip]:
                return
            
            self.stats['ipv4'] += 1
            
            if proto == 6:
                self.stats['tcp'] += 1
                tcp_header = self.parse_tcp(ip_payload)
                if tcp_header:
                    src_port, dest_port, seq, ack, flags, window, tcp_payload = tcp_header
                    
                    if self.filter_port and self.filter_port not in [src_port, dest_port]:
                        return
                    
                    if self.filter_protocol and self.filter_protocol.lower() != 'tcp':
                        return
                    
                    if self.verbose:
                        packet_structure = self.visualize_packet_structure(eth_proto, proto, src_port, dest_port)
                        
                        content = [
                            f"🔹 {packet_structure}",
                            "",
                            f"Source:      {src_ip}:{src_port}",
                            f"Destination: {dest_ip}:{dest_port}",
                            f"Sequence:    {seq}",
                            f"Acknowledge: {ack}",
                            f"Flags:       {self.get_tcp_flags(flags)}",
                            f"Window:      {window} bytes"
                        ]
                        
                        if tcp_payload:
                            content.append(f"Payload:     {len(tcp_payload)} bytes")
                            if len(tcp_payload) > 0:
                                content.append("")
                                content.append("Payload Preview (first 64 bytes):")
                                preview = tcp_payload[:64]
                                hex_preview = ' '.join(f'{b:02x}' for b in preview)
                                ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in preview)
                                content.append(f"HEX:   {hex_preview}")
                                content.append(f"ASCII: {ascii_preview}")
                        
                        self.print_packet_box("TCP PACKET", content)
                    
                    if self.extract_creds and tcp_payload:
                        self.extract_credentials(tcp_payload, src_ip, dest_ip, src_port, dest_port, 'TCP')
                    
                    if src_port == 80 or dest_port == 80:
                        self.stats['http'] += 1
                        if self.verbose:
                            self.parse_http(tcp_payload)
                    
                    elif src_port == 21 or dest_port == 21:
                        self.stats['ftp'] += 1
                        if self.verbose:
                            self.parse_ftp(tcp_payload)
                    
                    elif src_port == 23 or dest_port == 23:
                        self.stats['telnet'] += 1
                        if self.verbose:
                            print(f"[TELNET] Telnet traffic detected")
                    
                    elif src_port == 25 or dest_port == 25:
                        self.stats['smtp'] += 1
                        if self.verbose:
                            self.parse_smtp(tcp_payload)
            
            elif proto == 17:
                self.stats['udp'] += 1
                udp_header = self.parse_udp(ip_payload)
                if udp_header:
                    src_port, dest_port, length, udp_payload = udp_header
                    
                    if self.filter_port and self.filter_port not in [src_port, dest_port]:
                        return
                    
                    if self.filter_protocol and self.filter_protocol.lower() != 'udp':
                        return
                    
                    if self.verbose:
                        packet_structure = self.visualize_packet_structure(eth_proto, proto, src_port, dest_port)
                        
                        content = [
                            f"🔹 {packet_structure}",
                            "",
                            f"Source:      {src_ip}:{src_port}",
                            f"Destination: {dest_ip}:{dest_port}",
                            f"Length:      {length} bytes"
                        ]
                        
                        if udp_payload:
                            content.append(f"Payload:     {len(udp_payload)} bytes")
                            if len(udp_payload) > 0:
                                content.append("")
                                content.append("Payload Preview (first 64 bytes):")
                                preview = udp_payload[:64]
                                hex_preview = ' '.join(f'{b:02x}' for b in preview)
                                ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in preview)
                                content.append(f"HEX:   {hex_preview}")
                                content.append(f"ASCII: {ascii_preview}")
                        
                        self.print_packet_box("UDP PACKET", content)
                    
                    if src_port == 53 or dest_port == 53:
                        self.stats['dns'] += 1
                        if self.verbose:
                            print(f"[DNS] DNS query/response detected")
            
            elif proto == 1:
                self.stats['icmp'] += 1
                
                if self.filter_protocol and self.filter_protocol.lower() != 'icmp':
                    return
                
                icmp_header = self.parse_icmp(ip_payload)
                if icmp_header and self.verbose:
                    icmp_type, code, checksum, icmp_payload = icmp_header
                    packet_structure = self.visualize_packet_structure(eth_proto, proto)
                    
                    content = [
                        f"🔹 {packet_structure}",
                        "",
                        f"Source:      {src_ip}",
                        f"Destination: {dest_ip}",
                        f"Type:        {icmp_type} ({self.get_icmp_type(icmp_type)})",
                        f"Code:        {code}",
                        f"Checksum:    0x{checksum:04x}"
                    ]
                    
                    if icmp_payload and len(icmp_payload) > 0:
                        content.append(f"Payload:     {len(icmp_payload)} bytes")
                    
                    self.print_packet_box("ICMP PACKET", content)
        
        elif eth_proto == 0x0806:
            self.stats['arp'] += 1
            
            if self.filter_protocol and self.filter_protocol.lower() != 'arp':
                return
            
            arp_header = self.parse_arp(payload)
            if arp_header and self.verbose:
                hw_type, proto_type, operation, sender_mac, sender_ip, target_mac, target_ip = arp_header
                packet_structure = self.visualize_packet_structure(eth_proto)
                
                content = [
                    f"🔹 {packet_structure}",
                    "",
                    f"Operation:   {operation}",
                    f"Sender MAC:  {sender_mac}",
                    f"Sender IP:   {sender_ip}",
                    f"Target MAC:  {target_mac}",
                    f"Target IP:   {target_ip}",
                    f"HW Type:     {hw_type} (Ethernet: 1)",
                    f"Proto Type:  0x{proto_type:04x} (IPv4: 0x0800)"
                ]
                
                self.print_packet_box("ARP PACKET", content)
        
        elif eth_proto == 0x86DD:
            self.stats['ipv6'] += 1
            if self.verbose:
                packet_structure = self.visualize_packet_structure(eth_proto)
                content = [
                    f"🔹 {packet_structure}",
                    "",
                    f"Note: IPv6 packet detected but detailed parsing not yet implemented"
                ]
                self.print_packet_box("IPv6 PACKET", content)
        
        else:
            if self.verbose:
                print(f"\n[?] Unknown EtherType: 0x{eth_proto:04x}")
        
        if self.show_hex and self.verbose:
            print("\n  ===== HEX DUMP =====")
            print(self.hex_dump(data[:128]))
            print("  ===================\n")
    
    def parse_ethernet(self, data):
        try:
            dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
            return (self.format_mac(dest_mac), self.format_mac(src_mac), 
                    proto, data[14:])
        except struct.error:
            return None
    
    def parse_ipv4(self, data):
        try:
            version_header_length = data[0]
            version = version_header_length >> 4
            header_length = (version_header_length & 15) * 4
            ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
            return (version, header_length, ttl, proto, 
                    self.format_ipv4(src), self.format_ipv4(dest), 
                    data[header_length:])
        except (struct.error, IndexError):
            return None
    
    def parse_tcp(self, data):
        try:
            src_port, dest_port, seq, ack, offset_reserved_flags, window = struct.unpack('! H H L L H H', data[:16])
            offset = (offset_reserved_flags >> 12) * 4
            flags = offset_reserved_flags & 0x01FF
            return src_port, dest_port, seq, ack, flags, window, data[offset:]
        except (struct.error, IndexError):
            return None
    
    def parse_udp(self, data):
        try:
            src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
            return src_port, dest_port, length, data[8:]
        except (struct.error, IndexError):
            return None
    
    def parse_icmp(self, data):
        try:
            icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
            return icmp_type, code, checksum, data[4:]
        except (struct.error, IndexError):
            return None
    
    def parse_arp(self, data):
        try:
            hw_type, proto_type, hw_size, proto_size, operation = struct.unpack('! H H B B H', data[:8])
            sender_mac = self.format_mac(data[8:14])
            sender_ip = self.format_ipv4(data[14:18])
            target_mac = self.format_mac(data[18:24])
            target_ip = self.format_ipv4(data[24:28])
            
            operation_str = "Request" if operation == 1 else "Reply" if operation == 2 else "Unknown"
            return hw_type, proto_type, operation_str, sender_mac, sender_ip, target_mac, target_ip
        except (struct.error, IndexError):
            return None
    
    def parse_http(self, payload):
        try:
            http_data = payload.decode('utf-8', errors='ignore')
            if http_data.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS')):
                lines = http_data.split('\r\n')
                print(f"[HTTP Request] {lines[0]}")
                for line in lines[1:10]:
                    if line:
                        print(f"  {line}")
            elif http_data.startswith('HTTP/'):
                lines = http_data.split('\r\n')
                print(f"[HTTP Response] {lines[0]}")
        except:
            pass
    
    def parse_ftp(self, payload):
        try:
            ftp_data = payload.decode('utf-8', errors='ignore')
            if ftp_data:
                print(f"[FTP] {ftp_data.strip()}")
        except:
            pass
    
    def parse_smtp(self, payload):
        try:
            smtp_data = payload.decode('utf-8', errors='ignore')
            if smtp_data:
                print(f"[SMTP] {smtp_data.strip()[:100]}")
        except:
            pass
    
    def extract_credentials(self, payload, src_ip, dest_ip, src_port, dest_port, protocol):
        try:
            data = payload.decode('utf-8', errors='ignore')
            
            auth_match = re.search(r'Authorization: Basic ([A-Za-z0-9+/=]+)', data, re.IGNORECASE)
            if auth_match:
                try:
                    decoded = base64.b64decode(auth_match.group(1)).decode('utf-8')
                    cred = {
                        'type': 'HTTP Basic Auth',
                        'credentials': decoded,
                        'source': f"{src_ip}:{src_port}",
                        'destination': f"{dest_ip}:{dest_port}",
                        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                    self.captured_credentials.append(cred)
                    print(f"\n[!] CREDENTIALS FOUND!")
                    print(f"[!] Type: HTTP Basic Auth")
                    print(f"[!] {src_ip}:{src_port} -> {dest_ip}:{dest_port}")
                    print(f"[!] Credentials: {decoded}\n")
                except:
                    pass
            
            if 'USER ' in data or 'PASS ' in data:
                lines = data.split('\r\n')
                for line in lines:
                    if line.startswith('USER ') or line.startswith('PASS '):
                        cred = {
                            'type': 'FTP',
                            'credentials': line,
                            'source': f"{src_ip}:{src_port}",
                            'destination': f"{dest_ip}:{dest_port}",
                            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        }
                        self.captured_credentials.append(cred)
                        print(f"\n[!] CREDENTIALS FOUND!")
                        print(f"[!] Type: FTP")
                        print(f"[!] {src_ip}:{src_port} -> {dest_ip}:{dest_port}")
                        print(f"[!] Command: {line}\n")
            
            if 'AUTH LOGIN' in data or 'AUTH PLAIN' in data:
                cred = {
                    'type': 'SMTP Auth',
                    'credentials': data[:200],
                    'source': f"{src_ip}:{src_port}",
                    'destination': f"{dest_ip}:{dest_port}",
                    'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                self.captured_credentials.append(cred)
                print(f"\n[!] CREDENTIALS FOUND!")
                print(f"[!] Type: SMTP Auth")
                print(f"[!] {src_ip}:{src_port} -> {dest_ip}:{dest_port}\n")
            
            password_patterns = [
                r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'passwd["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'pwd["\']?\s*[:=]\s*["\']([^"\']+)["\']'
            ]
            
            for pattern in password_patterns:
                matches = re.finditer(pattern, data, re.IGNORECASE)
                for match in matches:
                    cred = {
                        'type': 'Generic Password',
                        'credentials': f"Password: {match.group(1)}",
                        'source': f"{src_ip}:{src_port}",
                        'destination': f"{dest_ip}:{dest_port}",
                        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                    self.captured_credentials.append(cred)
                    print(f"\n[!] POTENTIAL PASSWORD FOUND!")
                    print(f"[!] {src_ip}:{src_port} -> {dest_ip}:{dest_port}")
                    print(f"[!] Data: {match.group(0)}\n")
        except:
            pass
    
    def get_tcp_flags(self, flags):
        flag_strings = []
        if flags & 0x01: flag_strings.append('FIN')
        if flags & 0x02: flag_strings.append('SYN')
        if flags & 0x04: flag_strings.append('RST')
        if flags & 0x08: flag_strings.append('PSH')
        if flags & 0x10: flag_strings.append('ACK')
        if flags & 0x20: flag_strings.append('URG')
        return ','.join(flag_strings) if flag_strings else 'None'
    
    def get_icmp_type(self, icmp_type):
        icmp_types = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            4: 'Source Quench',
            5: 'Redirect',
            8: 'Echo Request',
            11: 'Time Exceeded',
            12: 'Parameter Problem',
            13: 'Timestamp',
            14: 'Timestamp Reply'
        }
        return icmp_types.get(icmp_type, f'Unknown ({icmp_type})')
    
    def format_mac(self, mac_bytes):
        return ':'.join(map('{:02x}'.format, mac_bytes))
    
    def format_ipv4(self, ip_bytes):
        return '.'.join(map(str, ip_bytes))
    
    def hex_dump(self, data, length=16, show_ascii=True):
        lines = []
        for i in range(0, len(data), length):
            chunk = data[i:i + length]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            
            if show_ascii:
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                lines.append(f"  {i:04x}:  {hex_part:<{length*3}}  |{ascii_part}|")
            else:
                lines.append(f"  {i:04x}:  {hex_part}")
        
        return '\n'.join(lines)
    
    def visualize_packet_structure(self, eth_proto, ip_proto=None, src_port=None, dest_port=None):
        layers = ["[Ethernet]"]
        
        if eth_proto == 0x0800:
            layers.append("[IPv4]")
            if ip_proto == 6:
                layers.append("[TCP]")
                if src_port == 80 or dest_port == 80:
                    layers.append("[HTTP]")
                elif src_port == 443 or dest_port == 443:
                    layers.append("[HTTPS]")
                elif src_port == 21 or dest_port == 21:
                    layers.append("[FTP]")
                elif src_port == 22 or dest_port == 22:
                    layers.append("[SSH]")
                elif src_port == 23 or dest_port == 23:
                    layers.append("[Telnet]")
                elif src_port == 25 or dest_port == 25:
                    layers.append("[SMTP]")
            elif ip_proto == 17:
                layers.append("[UDP]")
                if src_port == 53 or dest_port == 53:
                    layers.append("[DNS]")
                elif src_port == 67 or dest_port == 67:
                    layers.append("[DHCP]")
            elif ip_proto == 1:
                layers.append("[ICMP]")
        elif eth_proto == 0x0806:
            layers.append("[ARP]")
        elif eth_proto == 0x86DD:
            layers.append("[IPv6]")
        
        return " -> ".join(layers)
    
    def print_packet_box(self, title, content_lines):
        width = 70
        print(f"\n┌{'─' * (width-2)}┐")
        print(f"│ {title:<{width-4}} │")
        print(f"├{'─' * (width-2)}┤")
        for line in content_lines:
            if len(line) > width - 4:
                words = line.split()
                current_line = ""
                for word in words:
                    if len(current_line) + len(word) + 1 <= width - 4:
                        current_line += word + " "
                    else:
                        print(f"│ {current_line:<{width-4}} │")
                        current_line = word + " "
                if current_line:
                    print(f"│ {current_line:<{width-4}} │")
            else:
                print(f"│ {line:<{width-4}} │")
        print(f"└{'─' * (width-2)}┘")
    
    def print_statistics(self):
        print("\n" + "="*70)
        print("CAPTURE STATISTICS")
        print("="*70)
        print(f"Total Packets Captured: {self.packet_count}")
        print("\nProtocol Distribution:")
        for proto, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {proto.upper():15s}: {count:6d} ({count/self.packet_count*100:.2f}%)")
        print("="*70)
    
    def print_credentials(self):
        print("\n" + "="*70)
        print("CAPTURED CREDENTIALS")
        print("="*70)
        for i, cred in enumerate(self.captured_credentials, 1):
            print(f"\n[{i}] {cred['type']}")
            print(f"    Time: {cred['timestamp']}")
            print(f"    Source: {cred['source']}")
            print(f"    Destination: {cred['destination']}")
            print(f"    Data: {cred['credentials']}")
        print("="*70)
    
    def save_results(self):
        results = {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_packets': self.packet_count,
            'statistics': dict(self.stats),
            'credentials': self.captured_credentials
        }
        
        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=4)
        
        print(f"\n[*] Results saved to: {self.output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Packet Sniffer & Analyzer for Security Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
        Examples:
          sudo python3 packet_sniffer.py
          sudo python3 packet_sniffer.py -v
          sudo python3 packet_sniffer.py --protocol tcp --port 80
          sudo python3 packet_sniffer.py --ip 192.168.1.100 -v
          sudo python3 packet_sniffer.py -o capture.json
          sudo python3 packet_sniffer.py --protocol icmp -v
        
        Note: This tool requires root privileges (sudo)
        ''')
    )
    
    parser.add_argument('-i', '--interface', help='Network interface to sniff on')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('--protocol', choices=['tcp', 'udp', 'icmp', 'arp'], 
                       help='Filter by protocol')
    parser.add_argument('--port', type=int, help='Filter by port number')
    parser.add_argument('--ip', help='Filter by IP address')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Verbose output (show packet details)')
    parser.add_argument('--no-creds', action='store_true',
                       help='Disable credential extraction')
    parser.add_argument('--show-hex', action='store_true',
                       help='Show hex dump of packets (requires -v)')
    
    args = parser.parse_args()
    
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║        Packet Sniffer & Analyzer v1.1                ║
    ║        Advanced Network Traffic Analysis             ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    
    sniffer = PacketSniffer(
        interface=args.interface,
        output_file=args.output,
        filter_protocol=args.protocol,
        filter_port=args.port,
        filter_ip=args.ip,
        verbose=args.verbose,
        extract_creds=not args.no_creds,
        show_hex=args.show_hex
    )
    
    sniffer.start_sniffing()


if __name__ == '__main__':
    main()
