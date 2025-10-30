from scapy.all import rdpcap, TCP, IP
from collections import defaultdict
import re
import json

pcap_file = "wincapture.pcapng"
packets = rdpcap(pcap_file)

# Group packets into TCP flows
flows = defaultdict(list)
for pkt in packets:
    if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[TCP].payload:
        ip = pkt[IP]
        tcp = pkt[TCP]
        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        flows[key].append((tcp.seq, bytes(tcp.payload)))

# Reassemble flows
streams = {}
for key, frags in flows.items():
    frags.sort(key=lambda x: x[0])  # order by TCP seq
    data = b"".join(frag for _, frag in frags)
    streams[key] = data

# Regexes to detect request/response
http_request_re = re.compile(rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ", re.MULTILINE)
http_response_re = re.compile(rb"^HTTP/1\.[01] \d{3}", re.MULTILINE)


def decode_body(body_bytes, headers):
    if body_bytes is None or body_bytes == b"":
        return None
    ct = (headers.get("Content-Type", "") if headers else "").lower()
    text = body_bytes.decode(errors="replace")
    if "application/json" in ct or text.lstrip().startswith(("{", "[")):
        try:
            return json.loads(text)
        except Exception:
            pass
    return text

def parse_headers(header_bytes):
    headers = {}
    lines = header_bytes.split(b"\r\n")
    for line in lines[1:]:  # skip the request/status line
        if b": " in line:
            key, value = line.split(b": ", 1)
            headers[key.decode()] = value.decode()
    return headers


def split_http_messages(data):
    """
    Very naive HTTP splitter:
    - Finds headers terminated by \r\n\r\n
    - Treats the rest (headers + any following data until next header) as one message
    - No Content-Length or chunked handling, just dump raw
    """
    msgs = []
    while True:
        start = data.find(b"HTTP/")  # response
        req = re.search(http_request_re, data)
        if req and (start == -1 or req.start() < start):
            start = req.start()
        if start == -1:
            break

        # find end of headers
        hdr_end = data.find(b"\r\n\r\n", start)
        if hdr_end == -1:
            break

        # grab everything until next request/response or end of data
        next_req = re.search(http_request_re, data[hdr_end+4:])
        next_resp = re.search(http_response_re, data[hdr_end+4:])
        nexts = [m.start() + hdr_end + 4 for m in [next_req, next_resp] if m]
        end = min(nexts) if nexts else len(data)

        msgs.append(data[start:end])
        data = data[end:]
    return msgs

json_data = []

# Print every request and response
for key, stream in streams.items():
    for msg in split_http_messages(stream):
        if http_request_re.match(msg):
            print("----- HTTP REQUEST -----")
            print(msg.decode(errors="replace"))
            request = msg.decode(errors="replace")
            req_headers = parse_headers(msg.split(b"\r\n\r\n", 1)[0])
            req_body_bytes = msg.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in msg else b""
            req_body = decode_body(req_body_bytes, req_headers)
        elif http_response_re.match(msg):
            print("----- HTTP RESPONSE -----")
            print(msg.decode(errors="replace"))
            response = msg.decode(errors="replace")
            response_headers = parse_headers(msg.split(b"\r\n\r\n", 1)[0])
            resp_body_bytes = msg.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in msg else b""
            response_body = decode_body(resp_body_bytes, response_headers)
            json_data.append({
                                #"request": request, 
                              #  "response": response,

                           #   "req_header": req_headers,
                              "req_body": req_body,
                            #    "response_header": response_headers,
                                "response_body": response_body
                              })

json_output = json.dumps(json_data, indent=2)
# Save to file
with open("http_traffic_win.json", "w") as f:
    f.write(json_output)
