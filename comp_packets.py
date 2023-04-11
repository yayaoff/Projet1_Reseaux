import pyshark
import os
import matplotlib.pyplot as plt
import numpy as np

n_tcp = []
n_udp = []
n_other = []
for file in os.listdir("data/"):
    print("file : "  + file)
    capture = pyshark.FileCapture("data/" + file, display_filter="(tls) && !(ip.src == 192.168.1.38) && !(eth.src == 8c:dc:d4:38:2a:a2) && !(ip.src == 192.168.1.29) && !(ipv6.src == fe80::ba27:ebff:fe6b:b6aa) && !(ip.dst == 239.255.255.250) && !(ipv6.src == fe80::aa6a:bbff:fe81:1883) ")
    capture.load_packets()
    udp = 0
    tcp = 0
    other = 0
    for packet in capture :
        if packet.transport_layer == "UDP":
            udp +=1
        elif packet.transport_layer == "TCP":
            tcp +=1



    n_udp.append(udp)
    n_tcp.append(tcp)
barWidth = 0.4
br1 = np.arange(len(n_udp))
br2 = [x + barWidth for x in br1]
 
# Make the plot
plt.bar(br1, n_tcp, color ='orange', width = barWidth,
        edgecolor ='grey', label ='TCP')
plt.bar(br2, n_udp, color ='g', width = barWidth,
        edgecolor ='grey', label ='UDP')
 
# Adding Xticks
plt.xlabel('Fonctionnalités', fontweight ='bold', fontsize = 25)
plt.ylabel('Nombre de paquets échangés', fontweight ='bold', fontsize = 25)
plt.xticks([r+barWidth/2 for r in range(len(n_tcp))],
        ["Partage \n d'écran", "Appel audio",  'Chat','Tableau \n blanc', 'Enregistrement',"Chat \n dans l'appel",'Réactions',  "Appel vidéo", ], fontsize = 20)
 
plt.legend(fontsize=25)
plt.savefig('comp_ver_tls.png')
plt.show()
