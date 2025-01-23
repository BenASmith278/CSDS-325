import csv
import re
import argparse
import os

def parse_ping_output(output_file, csv_file):
    ip_regex = re.compile(r'PING [\w.-]+ \(([\d.]+)\)')
    bytes_regex = re.compile(r'(\d+) bytes from')
    rtt_regex = re.compile(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms')
    packets_regex = re.compile(r'(\d+) packets transmitted')
    domain_regex = re.compile(r'PING ([^\s]+)')

    with open(output_file, 'r') as infile, open(csv_file, 'w', newline='') as outfile:
        csv_writer = csv.writer(outfile)

        # header
        csv_writer.writerow(['Domain', 'IP', 'Bytes Transmitted', 'Packets Transmitted', 'RTT'])

        domain = None
        ip = None
        bytes_transmitted = None
        packets_transmitted = None
        avg_rtt = None

        for line in infile:
            # scan line by line and accumulate variables
            domain_match = domain_regex.search(line)
            if domain_match:
                domain = domain_match.group(1)

            ip_match = ip_regex.search(line)
            if ip_match:
                ip = ip_match.group(1)

            bytes_match = bytes_regex.search(line)
            if bytes_match:
                bytes_transmitted = bytes_match.group(1)

            packets_match = packets_regex.search(line)
            if packets_match:
                packets_transmitted = packets_match.group(1)

            rtt_match = rtt_regex.search(line)
            if rtt_match:
                avg_rtt = rtt_match.group(1)

            # write row once all columns found
            if ip and bytes_transmitted and packets_transmitted and avg_rtt:
                csv_writer.writerow([domain, ip, bytes_transmitted, packets_transmitted, avg_rtt])
                # reset variables
                ip = bytes_transmitted = packets_transmitted = avg_rtt = None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parse ping results and output to CSV.')
    parser.add_argument('input_file', type=str, help='The input file containing ping results.')
    args = parser.parse_args()

    input_filename = args.input_file
    base_name = os.path.splitext(input_filename)[0]
    output_csv_filename = f"{base_name}.csv"

    parse_ping_output(input_filename, output_csv_filename)