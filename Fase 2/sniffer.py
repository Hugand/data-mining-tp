from scapy.all import *
import time

import numpy as np # linear algebra
import pandas as pd # data processing, CSV file I/O (e.g. pd.read_csv)
import matplotlib.pyplot as plt
import seaborn as sns
import socket, struct
from sklearn.preprocessing import LabelEncoder

pd.set_option('display.max_columns', 500)

def ip2long(ip):
    """
    Convert an IP string to long
    """
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]

dt = pd.read_parquet('merged_dataset.gzip',)

df = np.array_split(dt, 10000)[0]
print("done")

df.loc[:,'IPV4_SRC_ADDR'] = df['IPV4_SRC_ADDR'].copy().apply(ip2long)
df.loc[:,'IPV4_DST_ADDR'] = df['IPV4_DST_ADDR'].copy().apply(ip2long)

from sklearn import preprocessing
le = preprocessing.LabelEncoder()
df['AttackEnc'] = le.fit_transform(df['Attack'])

enc = LabelEncoder()
df['L7_PROTO_NAME_ENC'] = enc.fit_transform(df.L7_PROTO_NAME)


from sklearn.ensemble import RandomForestClassifier
nums = df.select_dtypes(include=np.number)

X = nums.drop(columns=['Label', 'AttackEnc'], axis=1)
y = nums.AttackEnc

forest = RandomForestClassifier(random_state=2022)
forest.fit(X.values, y.values)




start_time = time.time()

def packet_handler(pkt):
    encoder = LabelEncoder()
    global start_time
    row = np.zeros(shape=(1,20))
    row[0][6] = 1                  #IN_PKTS N
    row[0][8] = 0                  #OUT_PKTS N
    row[0][10] = (time.time() - start_time)*1000#FLOW_DURATION_MILLISECONDS N
    start_time = time.time()
     
    if IP in pkt:
        start_time = time.time()
        row[0][0] = ip2long(pkt[IP].src )   #IPV4_SRC_ADDR
        row[0][2] = ip2long(pkt[IP].dst)    #IPV4_DST_ADDR
        row[0][4] = pkt[IP].proto  #PROTOCOL
        row[0][5] = pkt[IP].len    #IN_BYTES
        row[0][11] = pkt[IP].len   #MIN_IP_PKT_LEN N
        row[0][12] = pkt[IP].len   #MAX_IP_PKT_LEN N
        row[0][13] = 0             #RETRANSMITTED_IN_BYTES Assumir tudo a 0
        row[0][14] = 0             #RETRANSMITTED_IN_PKTS Assumir tudo a 0
        row[0][15] = 0             #RETRANSMITTED_OUT_BYTES Assumir tudo a 0
        row[0][16] = 0             #RETRANSMITTED_OUT_PKTS Assumir tudo a 0
        row[0][17] = 0             #TCP_WIN_MAX_IN
        row[0][18] = 0             #TCP_WIN_MAX_OUT Assumir tudo  0
        n_value = 'Unknown'
        encoder.fit([n_value])
        row[0][19] = encoder.transform([n_value] )[0]   #L7_PROTO_NAME


        if TCP in pkt or UDP in pkt:
            if TCP in pkt:
                row[0][1] = pkt[TCP].sport #L4_SRC_PORT
                row[0][3] = pkt[TCP].dport #L4_DST_PORT
                row[0][7] = len(pkt[IP]) - (pkt[IP].ihl * 4) - (pkt[TCP].dataofs * 4)#OUT_BYTES
                row[0][9] = pkt[TCP].flags.value
                row[0][17] = pkt[TCP].window #TCP_WIN_MAX_IN((nao é a max)
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
                    encoder.fit([protocol_name])
                    row[0][19] = encoder.transform([protocol_name])[0]  #L7_PROTO_NAME

            
            if UDP in pkt:
                row[0][1] = pkt[UDP].sport #L4_SRC_PORT
                row[0][3] = pkt[UDP].dport #L4_DST_PORT
                row[0][7] = len(pkt[IP]) - (pkt[IP].ihl * 4) - 8#OUT_BYTES
                row[0][9] = 0 #TCP_FLAGS (0 qnd é UDP)

            if row[0][7] > 0:
                row[0][8] = 1

        print(le.inverse_transform(forest.predict(row))[0])


sniff(prn=packet_handler)

