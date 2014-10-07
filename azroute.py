import socket
import urllib
import json
import pickle
import pandas as pd
import argparse
from datetime import datetime


def get_geoip(url):
    geoip_url = "http://dazzlepod.com/ip/{}.json".format(url)
    req = urllib.request.urlopen(geoip_url)
    reqdata = req.read().decode()
    return json.loads(reqdata)


def geoip_to_str(geoip):
    s = ""
    country = geoip['country'].strip()
    region = geoip['region'].strip()
    city = geoip['city'].strip()
    organization = geoip['organization'].strip()
    hostname = geoip['hostname'].strip()
    s += hostname
    if country or region or city:
        s += " ("
    if country:
        s += "{}, ".format(country)
    if region:
        s += "{}, ".format(region)
    if city:
        s += "{}, ".format(city)
    if organization:
        if len(organization) > 15:
            organization = organization[:15] + "..."
        s += "{}, ".format(organization)
    s = s[:-2]
    if country or region or city:
        s += ")"
    return s


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="traceroute with geoip")
    parser.add_argument("hostname", help="host to run traceroute against")
    parser.add_argument("-p", type=int, default=33434,
                        help="port to use for ICMP responses")
    parser.add_argument("--max-hops", type=int, default=30, help="max hops/ttl")
    parser.add_argument("-w", type=float, default=5,
                        help="max seconds to wait for a hop")
    args = parser.parse_args()

    dest_name = args.hostname
    port = args.p
    max_hops = args.max_hops
    socket.setdefaulttimeout(args.w)

    dest_addr = socket.gethostbyname(dest_name)
    print("Tracing route to {} ...".format(geoip_to_str(get_geoip(dest_addr))))
    icmp = socket.getprotobyname("icmp")
    udp = socket.getprotobyname("udp")
    ttl = 1
    output_data = []
    output_indices = []
    while True:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        recv_socket.bind(("", port))
        time_sent = datetime.utcnow()
        send_socket.sendto(b"", (dest_addr, port))
        curr_addr = None
        curr_geoip = None
        try:
            _, curr_addr = recv_socket.recvfrom(512)
            time_received = datetime.utcnow()
            ms_elapsed = (time_received - time_sent).total_seconds() * 1000
            curr_addr = curr_addr[0]
            curr_geoip = get_geoip(curr_addr)
            # print(curr_geoip)
            # curr_name = socket.gethostbyaddr(curr_addr)[0]
        except socket.error:
            pass
        finally:
            send_socket.close()
            recv_socket.close()
        output = "{}: ".format(ttl)
        if curr_addr:
            curr_odata = {"addr": curr_addr, "geoip": curr_geoip, "latency": ms_elapsed}
            output_data.append(curr_odata)
            output_indices.append(ttl)
            if curr_geoip:
                if 'error' in curr_geoip:
                    estr = curr_geoip['error']
                    if "is a private IP address" in estr:
                        output += "{} (Private IP)".format(curr_addr)
                    else:
                        output += "{} (Error: {})".format(curr_addr, estr)
                else:
                    output += geoip_to_str(curr_geoip)
            else:
                output += str(curr_addr)
            output += ", {:.0f}ms".format(ms_elapsed)
        else:
            output += "*"
        print(output)
        if curr_addr == dest_addr or ttl == max_hops:
            break
        ttl += 1
    out_df = pd.DataFrame(output_data, index=output_indices)
    pickle.dump(out_df, open('output.p', 'wb'))
