from collections import Counter
import collections

file_in = open('router1.log', 'r')
file_out = open(r'outfile.txt', 'w')

lines = file_in.readlines()

def process_line(line):
    class Line:
        def __init__(self, date_time, ip, code, payload):
            self.date_time = date_time
            self.ip =  ip
            self.code = code
            self.payload = payload

    
    # split lines by spaces
    segments = line.split(" ")

    # get length of arrays to retrieve payload
    last_index = len(segments)
    indices = []

    # fill list with all remaining indices
    for i in range(6, last_index):
        indices.append(i)

    # identify segments using index in list
    return Line(
        date_time = segments[0] + ' ' + segments[1] + ' ' + segments[2],
        ip = segments[3],
        code = segments[5],
        payload = [segments[i] for i in indices],
        )

# transform lines to objects for later analysis
processed_lines = []
for line in lines:
    line = process_line(line)
    processed_lines.append(line)

# helper function for analyzing code: link_3 lines
def process_link_3(line):
    class Link3:
        def __init__(self, interface, status, date_time):
            self.interface = interface
            self.status = status
            self.date_time = date_time

    payload = line.payload

    return Link3(
        interface = payload[1],
        status = payload[-1],
        date_time = line.date_time
    )


def process_sec_6_log_pd(line):
    class Sec6Pd:
        def __init__(self, ip, packets):
            self.ip = ip
            self.packets = packets

    payload = line.payload
    # print(payload)
    return Sec6Pd(
        ip = payload[4],
        packets = payload[-2]
    )


def process_sec_6_log_p(line):
    class Sec6P:
        def __init__(self, ip, packets, protocol, permission):
            self.ip = ip
            self.packets = packets
            self.protocol = protocol
            self.permission = permission

    payload = line.payload
    # file_out.writelines(payload)
    return Sec6P(
        ip = payload[4],
        packets = payload[7],
        protocol = payload[3],
        permission = payload[2]
    )


def process_span_tree_2(line):
    class Spantree2:
        def __init__(self, vlan):
            self.vlan = vlan

    payload = line.payload
    # print(payload)
    return Spantree2(
        vlan = payload[3]
    )



# initialize lists for sorting
link_3 = []
sec_6_log_pd = []
sec_6_log_p = []
span_tree_2 = []


# categorize lines based on code
for line in processed_lines:
    # get code, cut last character
    code = line.code[:-1]
    if code == '%LINK-3-UPDOWN':
        processed_line = process_link_3(line)
        link_3.append(processed_line)
    if code ==  '%SEC-6-IPACCESSLOGDP':
        processed_line = process_sec_6_log_pd(line)
        sec_6_log_pd.append(processed_line)
    if code == '%SEC-6-IPACCESSLOGP':
        processed_line = process_sec_6_log_p(line)
        sec_6_log_p.append(processed_line)
    if code == '%SPANTREE-2-BLOCK_PVID_LOCAL':
        processed_line = process_span_tree_2(line)
        span_tree_2.append(processed_line)

# link_3.sort(key = lambda line: line.interface)
# sorted_result = Counter(getattr(line, 'interface') for line in link_3)

c = Counter()
for line in link_3:
    interface = line.interface
    c[interface] += 1
file_out.writelines('De 5 interfaces die het vaakst up of daan zijn geweest zijn: \n' + str(c.most_common(5)) + '\n\n')

packets = 0
for line in sec_6_log_pd:
    packets += int(line.packets)
file_out.writelines('In totaal zijn ' + str(packets) + ' tegengehouden op basis van informatie in %SEC-6-IPACCESSLOGDP regels\n\n')

c = Counter()
for line in sec_6_log_p:
    ip = line.ip
    if (line.protocol == 'tcp') and (line.permission == 'DENIED'):
        c[ip] += int(line.packets)
file_out.writelines('De top 20 van IP adressen waarvandaan de meeste TCP packets tegengehouden zijn, op basis van informatie in %SEC-6-IPACCESSLOGP regels.\n' + str(c.most_common(20)) + '\n\n')

# spanning_tree_

        









