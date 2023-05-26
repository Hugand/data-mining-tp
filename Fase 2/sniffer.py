from scapy.all import *
import time

import pandas as pd # data processing, CSV file I/O (e.g. pd.read_csv)
import socket, struct
from sklearn.preprocessing import LabelEncoder
import pickle


forestAttack = pickle.load(open('model_attack.sav', 'rb'))
forestLabel = pickle.load(open('model.sav', 'rb'))
attack_encoder = pickle.load(open('attack_encoder.sav', 'rb'))
l7_pn_encoder = pickle.load(open('l7_pn.sav', 'rb'))

start_time = time.time()

#
# ['L4_SRC_PORT', 'TCP_WIN_MAX_IN', 'MAX_IP_PKT_LEN', 'L7_PROTO_NAME', 'L4_DST_PORT', 'MIN_IP_PKT_LEN', 'FLOW_DURATION_MILLISECONDS',
#  'IN_BYTES', 'TCP_WIN_MAX_OUT', 'SRC_TO_DST_SECOND_BYTES_TOTAL', 'SRC_TO_DST_SECOND_BYTES_MEAN', 'IN_PKTS']
#
def packet_handler(pkt): 
    global start_time

    data = {
        'L4_SRC_PORT': None,
        'TCP_WIN_MAX_IN': 0,
        'MAX_IP_PKT_LEN': None,
        'L7_PROTO_NAME': None,
        'L4_DST_PORT': None,
        'MIN_IP_PKT_LEN': None,
        'FLOW_DURATION_MILLISECONDS': None,
        'IN_BYTES': None,
        'TCP_WIN_MAX_OUT': 0,
        'SRC_TO_DST_SECOND_BYTES_TOTAL': None,
        'SRC_TO_DST_SECOND_BYTES_MEAN': None,
        'IN_PKTS': 1,
    }
    #Exemplo de Syn attack
    data2 = {
        'L4_SRC_PORT': 49726,
        'TCP_WIN_MAX_IN': 1024,
        'MAX_IP_PKT_LEN': 0,
        'L7_PROTO_NAME': 332,
        'L4_DST_PORT': 15149,
        'MIN_IP_PKT_LEN': 0,
        'FLOW_DURATION_MILLISECONDS': 1,
        'IN_BYTES': 120,
        'TCP_WIN_MAX_OUT': 0,
        'SRC_TO_DST_SECOND_BYTES_TOTAL': 44.0,
        'SRC_TO_DST_SECOND_BYTES_MEAN': 44.0,
        'IN_PKTS': 1000,
    }

    data['FLOW_DURATION_MILLISECONDS'] = (time.time() - start_time)
    start_time = time.time()
     
    if IP in pkt and (TCP in pkt or UDP in pkt):
        start_time = time.time()
        data['IN_BYTES'] = pkt[IP].len
        data['MIN_IP_PKT_LEN'] = pkt[IP].len
        data['MAX_IP_PKT_LEN'] = pkt[IP].len
        if data['FLOW_DURATION_MILLISECONDS'] / 1000 > 0:
            data['SRC_TO_DST_SECOND_BYTES_MEAN'] = pkt[IP].len / (data['FLOW_DURATION_MILLISECONDS'] /1000)
            data['SRC_TO_DST_SECOND_BYTES_TOTAL'] = pkt[IP].len / (data['FLOW_DURATION_MILLISECONDS']/ 1000)
        else:
            data['SRC_TO_DST_SECOND_BYTES_MEAN'] = pkt[IP].len
            data['SRC_TO_DST_SECOND_BYTES_TOTAL'] = pkt[IP].len

        if TCP in pkt or UDP in pkt:
            if TCP in pkt:
                data['L4_SRC_PORT'] = pkt[TCP].sport
                data['L4_DST_PORT'] = pkt[TCP].dport
                data['TCP_WIN_MAX_IN'] = pkt[TCP].window
                
                try:
                    l7 = socket.getservbyport(int(pkt[TCP].sport))
                    l7 = l7.upper()
                    try:
                        data['L7_PROTO_NAME'] =  l7_pn_encoder.transform([l7])[0]
                    except ValueError:
                        data['L7_PROTO_NAME'] = l7_pn_encoder.transform(["Unknown"])[0]
                    
                except socket.error:
                    data['L7_PROTO_NAME'] = l7_pn_encoder.transform(["Unknown"])[0]


            if UDP in pkt:
                data['L4_SRC_PORT'] = pkt[UDP].sport
                data['L4_DST_PORT'] = pkt[UDP].dport
                
                try:
                    l7 = socket.getservbyport(int(pkt[UDP].sport),'udp')
                    l7 = l7.upper()
                    try:
                        data['L7_PROTO_NAME'] =  l7_pn_encoder.transform([l7])[0]
                    except ValueError:
                        data['L7_PROTO_NAME'] = l7_pn_encoder.transform(["Unknown"])[0]
                except socket.error:
                    data['L7_PROTO_NAME'] = l7_pn_encoder.transform(["Unknown"])[0]
                
        label = forestLabel.predict(pd.DataFrame([data]))
        if label > 0:
            prediction=forestAttack.predict(pd.DataFrame([data]))
            pred = attack_encoder.inverse_transform(prediction)[0]
            print(pkt.summary(),"           TYPE:", pred)
        #else:
        #    print(pkt.summary(),"           TYPE: Bening")

sniff(prn=packet_handler)

