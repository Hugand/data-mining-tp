from scapy.all import *
import time

import numpy as np # linear algebra
import pandas as pd # data processing, CSV file I/O (e.g. pd.read_csv)
import matplotlib.pyplot as plt
import seaborn as sns
import socket, struct
from sklearn.preprocessing import LabelEncoder
import pickle

pd.set_option('display.max_columns', 500)

def ip2long(ip):
    """
    Convert an IP string to long
    """
    ip = '.'.join(ip.split('.')[:-1] + ['0'])
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]

forest = pickle.load(open('model.sav', 'rb'))
attack_encoder = pickle.load(open('attack_encoder.sav', 'rb'))
l7_pn_encoder = pickle.load(open('l7_pn.sav', 'rb'))

start_time = time.time()

#
# ['IPV4_DST_ADDR', 'IPV4_SRC_ADDR', 'L7_PROTO_NAME', 'L4_SRC_PORT', 'MAX_IP_PKT_LEN', 'L4_DST_PORT', 'TCP_WIN_MAX_IN', 'FLOW_DURATION_MILLISECONDS',
# 'MIN_IP_PKT_LEN', 'TCP_WIN_MAX_OUT', 'SRC_TO_DST_SECOND_BYTES_MEAN', 'IN_BYTES', 'SRC_TO_DST_SECOND_BYTES_TOTAL', 'IN_PKTS', 'PROTOCOL', 'TCP_FLAGS']
#
def packet_handler(pkt):
    encoder = LabelEncoder()
    global start_time

    data = {
        'IPV4_DST_ADDR': None,
        'IPV4_SRC_ADDR': None,
        'L7_PROTO_NAME': None,
        'L4_SRC_PORT': None,
        'MAX_IP_PKT_LEN': None,
        'L4_DST_PORT': None,
        'TCP_WIN_MAX_IN': 0,
        'FLOW_DURATION_MILLISECONDS': None,
        'MIN_IP_PKT_LEN': None,
        'TCP_WIN_MAX_OUT': 0,
        'SRC_TO_DST_SECOND_BYTES_MEAN': None,
        'IN_BYTES': None,
        'SRC_TO_DST_SECOND_BYTES_TOTAL': None,
        'IN_PKTS': 1,
        'PROTOCOL': None,
        'TCP_FLAGS': None
    }


    row = np.zeros(shape=(1,20))
    data['FLOW_DURATION_MILLISECONDS'] = (time.time() - start_time)*1000
    # row[0][6] = 1                  #IN_PKTS N
    # row[0][8] = 0                  #OUT_PKTS N
    # row[0][10] = (time.time() - start_time)*1000#FLOW_DURATION_MILLISECONDS N
    start_time = time.time()
     
    if IP in pkt:
        start_time = time.time()
        data['IPV4_SRC_ADDR'] = ip2long(pkt[IP].src)
        data['IPV4_DST_ADDR'] = ip2long(pkt[IP].dst)
        data['PROTOCOL'] = pkt[IP].proto
        data['IN_BYTES'] = pkt[IP].len
        data['MIN_IP_PKT_LEN'] = pkt[IP].len
        data['MAX_IP_PKT_LEN'] = pkt[IP].len
        data['L7_PROTO_NAME'] = l7_pn_encoder.transform(['Unknown'])[0]
        data['L7_PROTO_NAME'] = l7_pn_encoder.transform(['Unknown'])[0]
        data['SRC_TO_DST_SECOND_BYTES_MEAN'] = pkt[IP].len
        data['SRC_TO_DST_SECOND_BYTES_TOTAL'] = pkt[IP].len

        # row[0][0] = ip2long(pkt[IP].src )   #IPV4_SRC_ADDR
        # row[0][2] = ip2long(pkt[IP].dst)    #IPV4_DST_ADDR
        # row[0][4] = pkt[IP].proto  #PROTOCOL
        # row[0][5] = pkt[IP].len    #IN_BYTES
        # row[0][11] = pkt[IP].len   #MIN_IP_PKT_LEN N
        # row[0][12] = pkt[IP].len   #MAX_IP_PKT_LEN N
        # row[0][13] = 0             #RETRANSMITTED_IN_BYTES Assumir tudo a 0
        # row[0][14] = 0             #RETRANSMITTED_IN_PKTS Assumir tudo a 0
        # row[0][15] = 0             #RETRANSMITTED_OUT_BYTES Assumir tudo a 0
        # row[0][16] = 0             #RETRANSMITTED_OUT_PKTS Assumir tudo a 0
        # row[0][17] = 0             #TCP_WIN_MAX_IN
        # row[0][18] = 0             #TCP_WIN_MAX_OUT Assumir tudo  0
        # n_value = 'Unknown'
        # encoder.fit([n_value])
        # row[0][19] = encoder.transform([n_value] )[0]   #L7_PROTO_NAME


        if TCP in pkt or UDP in pkt:
            if TCP in pkt:
                data['L4_SRC_PORT'] = pkt[TCP].sport
                data['L4_DST_PORT'] = pkt[TCP].ldporten
                data['TCP_FLAGS'] = pkt[TCP].flags.value
                data['TCP_WIN_MAX_IN'] = pkt[TCP].window

                # row[0][1] = pkt[TCP].sport #L4_SRC_PORT
                # row[0][3] = pkt[TCP].dport #L4_DST_PORT
                # row[0][7] = len(pkt[IP]) - (pkt[IP].ihl * 4) - (pkt[TCP].dataofs * 4)#OUT_BYTES
                # row[0][9] = pkt[TCP].flags.value
                # row[0][17] = pkt[TCP].window #TCP_WIN_MAX_IN((nao é a max)
                if Raw in pkt:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    # Protocol identification logic
                    if 'HTTP' in payload:
                        protocol_name = 'HTTP'
                    elif 'FTP' in payload:
                        protocol_name = 'FTP'
                    elif 'SMTP' in payload:
                        protocol_name = 'SMTP'
                    else:
                        protocol_name = 'Unknown'
                    # encoder.fit([protocol_name])
                    # row[0][19] = encoder.transform([protocol_name])[0]  #L7_PROTO_NAME
                    data['L7_PROTO_NAME'] = l7_pn_encoder.transform([protocol_name])[0]

            if UDP in pkt:
                data['L4_SRC_PORT'] = pkt[UDP].sport
                data['L4_DST_PORT'] = pkt[UDP].dport
                data['TCP_FLAGS'] = 0
                # row[0][1] = pkt[UDP].sport #L4_SRC_PORT
                # row[0][3] = pkt[UDP].dport #L4_DST_PORT
                # row[0][7] = len(pkt[IP]) - (pkt[IP].ihl * 4) - 8#OUT_BYTES
                # row[0][9] = 0 #TCP_FLAGS (0 qnd é UDP)

            # if row[0][7] > 0:
            #     row[0][8] = 1

        print(attack_encoder.inverse_transform(forest.predict(pd.DataFrame([row]))[0])

sniff(prn=packet_handler)

