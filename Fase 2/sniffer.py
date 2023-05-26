from scapy.all import *
import time

import numpy as np # linear algebra
import pandas as pd # data processing, CSV file I/O (e.g. pd.read_csv)
import matplotlib.pyplot as plt
import seaborn as sns
import socket, struct
from sklearn.preprocessing import LabelEncoder
import pickle

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
        'TCP_FLAGS': 0
    }

    data['FLOW_DURATION_MILLISECONDS'] = (time.time() - start_time)
    start_time = time.time()
     
    if IP in pkt and (TCP in pkt or UDP in pkt):
        start_time = time.time()
        data['IPV4_SRC_ADDR'] = ip2long(pkt[IP].src)
        data['IPV4_DST_ADDR'] = ip2long(pkt[IP].dst)
        data['PROTOCOL'] = pkt[IP].proto
        data['IN_BYTES'] = pkt[IP].len
        data['MIN_IP_PKT_LEN'] = pkt[IP].len
        data['MAX_IP_PKT_LEN'] = pkt[IP].len
        if data['FLOW_DURATION_MILLISECONDS'] > 0:
            data['SRC_TO_DST_SECOND_BYTES_MEAN'] = pkt[IP].len / data['FLOW_DURATION_MILLISECONDS']
            data['SRC_TO_DST_SECOND_BYTES_TOTAL'] = pkt[IP].len / data['FLOW_DURATION_MILLISECONDS']
        else:
            data['SRC_TO_DST_SECOND_BYTES_MEAN'] = pkt[IP].len
            data['SRC_TO_DST_SECOND_BYTES_TOTAL'] = pkt[IP].len

        if TCP in pkt or UDP in pkt:
            if TCP in pkt:
                data['L4_SRC_PORT'] = pkt[TCP].sport
                data['L4_DST_PORT'] = pkt[TCP].dport
                data['TCP_FLAGS'] = pkt[TCP].flags.value
                data['TCP_WIN_MAX_IN'] = pkt[TCP].window

                try:
                    l7 = socket.getservbyport(int(pkt[TCP].sport))
                    data['L7_PROTO_NAME'] =  l7_pn_encoder.transform([l7])[0]
                except socket.error:
                    data['L7_PROTO_NAME'] = l7_pn_encoder.transform(["Unknown"])[0]

            if UDP in pkt:
                data['L4_SRC_PORT'] = pkt[UDP].sport
                data['L4_DST_PORT'] = pkt[UDP].dport
                data['TCP_FLAGS'] = 0

                try:
                    l7 = socket.getservbyport(int(pkt[TCP].sport),'udp')
                    data['L7_PROTO_NAME'] =  l7_pn_encoder.transform([l7])[0]
                except socket.error:
                    data['L7_PROTO_NAME'] = l7_pn_encoder.transform(["Unknown"])[0]


        prediction=forest.predict(pd.DataFrame([data]))
        pred = attack_encoder.inverse_transform(prediction)[0]
        if pred != "Benign":
            print(pred)

sniff(prn=packet_handler)

