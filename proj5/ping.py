import argparse
import datetime
import subprocess
import time

def ping_domain(domain, count, rate_limit, output_file):
    with open(output_file, 'w') as f:
        for i in range(count):
            start_time = datetime.datetime.now()
            # ping
            process = subprocess.Popen(['ping', '-c', '1', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            f.write(stdout.decode('utf-8'))

            end_time = datetime.datetime.now()
            duration = end_time - start_time
            # debugging info
            print(f"PING #{i}\tDuration: {duration.total_seconds()}")

            # sleep for remainder of time in rate_limit
            sleep_time = datetime.timedelta(seconds = 1.0 / rate_limit) - duration
            time.sleep(max(sleep_time.total_seconds(), 0))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Ping a domain at a specified rate.')
    parser.add_argument('domain', type=str, help='The domain name to ping.')
    parser.add_argument('--outfilename', type=str, default=None, help='Filename to output results.')
    parser.add_argument('--count', type=int, default=1000, help='Number of ping requests to send.')
    args = parser.parse_args()

    # default to domain_ping_results_timenow.txt
    domain = args.domain    
    if (not args.outfilename):
        current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        sanitized_domain = domain.replace('.', '_')
        outfile = f"{sanitized_domain}_ping_results_{current_time}.txt"
    else:
        outfile = args.outfilename

    ping_domain(domain, args.count, 5, outfile)