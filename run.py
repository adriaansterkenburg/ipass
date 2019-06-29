file_in = open('router2.log', 'r')
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
        payload = [segments[i] for i in indices]
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


# initialize lists for sorting
link_3 = []
sec_6 = []
span_tree_2 = []

# categorize lines based on code
for line in processed_lines:
    # get code, cut last character
    code = line.code[:-1]
    print(code)
    if code == '%LINK-3-UPDOWN':
        processed_line = process_link_3(line)
        link_3.append(processed_line)
    if code ==  '%SEC-6-IPACCESSLOGS':
        print('*** %SEC-6-IPACCESSLOGS')
    if code == '%SPANTREE-2-BLOCK_PVID_LOCAL': 
        print('*** %SPANTREE-2-BLOCK_PVID_LOCAL')


        









