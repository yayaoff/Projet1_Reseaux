import pyshark as ps
import dns.resolver
import sys
import matplotlib.pyplot as plt
import numpy as np
import os
from datetime import datetime, timedelta
import socket 

request_types = {
    '1': 'A',
    '12': "PTR",
    '28': 'AAAA',
    '33': 'SRV',
    '65': 'HTTPS'
}

def get_packets(filename,filter):
    return ps.FileCapture("data/"+filename,display_filter=filter)

def get_infos(file_capture):
    file_capture.load_packets()
    d = {}
    d['tot_dns'] = 0
    d['start'] = str(file_capture[0].sniff_time)
    d['end'] = str(file_capture[file_capture.__len__() - 1].sniff_time)
    d['requests'] = {}
    d['requests']['1'] = 0
    d['requests']['12'] = 0
    d['requests']['28'] = 0
    d['requests']['33'] = 0
    d['requests']['65'] = 0
    d['request ip type'] = []
    d['Ip versions'] = []
    d['tot STUN'] = 0
    d['ip dst'] = []
    tot_packets = 0
    tot_duration = 0
    tot_length = 0

    for pckt in file_capture:

        if 'DNS' in pckt:
            d['tot_dns'] += 1

            name = pckt.dns.qry_name
            time = pckt.sniff_time
            if(name not in d.keys()):
                d[name] = {}
                d[name]['times'] = [str(time)]
                d[name]['qry_types'] = []
                d[name]['auth serv'] = []
            elif(name in d.keys()):
                d[name]['times'].append(str(time))

            tot_auth = int(pckt.dns.count_auth_rr)
            if(tot_auth >= 1):
                d[name]['auth serv'].append(pckt.dns.resp_name)

            type_qry = str(pckt.dns.qry_type)
            d[name]['qry_types'].append(type_qry)
            d['requests'][type_qry] += 1

            if 'response' not in pckt.dns.flags.showname:
                d['request ip type'].append(type_qry)

        if 'IP' in pckt:
            d['Ip versions'].append(pckt['IP'].version)
            if pckt.ip.dst and pckt.ip.dst not in d['ip dst'] :
                d['ip dst'].append(pckt.ip.dst)
        if 'STUN' in pckt:
            d['tot STUN'] += 1
        
        tot_packets += 1
        tot_duration += float(pckt.captured_length)
        tot_length += float(pckt.length)
    
    d['tot'] = tot_packets
    d['tot time'] = (file_capture[file_capture.__len__() - 1].sniff_time - file_capture[0].sniff_time) / timedelta(minutes=1)
    d['tot length'] = tot_length
            
    return d

def print_infos(infos,file):
    original_stdout = sys.stdout
   
    with open('infos/'+file, 'w') as f:
        sys.stdout = f
        print('File <'+str(file)+'> started at ' + str(infos['start']) + ' and finished ' + str(infos['end']))
        print('Total of domain names for test file ' + str(file) + ' = ' + str(len(infos.keys())-6))
        print('Total of packets :' + str(infos['tot']))
        print('Lasted for ' + str(infos['tot time']) + ' minutes\n')
        print('Total volume :' + str(infos['tot length']) + '\n')
        for key in infos.keys():
            if(key=='start' or key =='end' or key == 'requests' or key == 'tot_dns' or key == 'request ip type' or key == 'Ip versions' or key == 'tot' or key == 'tot time' or key == 'tot length' or key == 'tot STUN' or key == 'ip dst'  ):
                pass
            else:
                print('\n')
                print("Domain name <" + str(key) + ">\n")
                print("     Times : ")
                for time in infos[key]['times']:
                    print('         '+time)
                print("\n     Authoritative server(s) : ")
                for serv in infos[key]['auth serv']:
                    print('         '+str(serv))
                print('\n     Type requests:')
                for type in infos[key]['qry_types']:
                    print('         '+request_types[type])
        # print('\nTypes of dns requests for ip adress : ')
        # for t in infos['request ip type']:
        #     print('     '+str(request_types[t]))
        print('\n')
        for req in infos['requests'].keys():
            print('Total of  '+ request_types[req] + ' = ' + str(infos['requests'][req]) )
        print('\n')
        print('Ip destinations')
        for ip_dst in infos['ip dst']:
            print(str(ip_dst))
        # print('Ip versions : \n')
        # for version in infos['Ip versions']:
        #     print(str(version))
        sys.stdout = original_stdout

nr = 1   
filter = '!(ip.src == 192.168.1.38) && !(eth.src == 8c:dc:d4:38:2a:a2) && !(ip.src == 192.168.1.29) && !(ipv6.src == fe80::ba27:ebff:fe6b:b6aa) && !(ip.dst == 239.255.255.250) && !(ipv6.src == fe80::aa6a:bbff:fe81:1883)'
tot_dns = 0

tot_dom_names = []

tot_stun = []

tot__ip_a = []
tot_ip_aaaa = []
tot_ip_srv = []
tot_ip_https = []

tot_ipv4 = []
tot_ipv6 = []

tot_a = []
tot_aaaa = []
tot_srv = []
tot_https = []

tot_pckts = []
tot_length = []

for file in os.listdir("data/"):
    print("Capturing file : "+str(file))
    capture = get_packets(file, filter)
    infos = get_infos(capture)

    tot_dns += infos['tot_dns']
    tot_stun.append(infos['tot STUN'])

    a_ip = 0
    aaaa_ip = 0
    srv_ip = 0
    https_ip = 0

    for type in infos['request ip type']:
        if(type=='1'):
            a_ip += 1
        elif(type=='28'):
            aaaa_ip += 1
        elif(type=='33'):
            srv_ip += 1
        elif(type=='65'):
            https_ip += 1

    ipv4 = 0
    ipv6 = 0
    for version in infos['Ip versions']:
        if version == '4':
            ipv4 += 1
        elif version == '6':
            ipv6 += 1
    tot_ipv4.append(ipv4)
    tot_ipv6.append(ipv6)

    tot_a.append(a_ip)
    tot_aaaa.append(aaaa_ip)
    tot_srv.append(srv_ip)
    tot_https.append(https_ip)

    tot_dom_names.append(len(infos.keys())-11)

    tot_pckts.append(infos['tot']/infos['tot time'])
    tot_length.append(infos['tot length']/infos['tot time'])

    print_infos(infos,'file'+str(nr)+'.txt')
    nr += 1
    capture.close()

# print(tot_a)
# print(tot_aaaa)
# print(tot_srv)
# print(tot_https)

# -----------------------------------------------------------------------------------
# PLOTS :
# -----------------------------------------------------------------------------------

barWidth = 0.2

# Domain Names :

fig_dom_name =  plt.figure(figsize=(20,15))
fig_dom_name = plt.title('Noms de domaine résolus selon la fonctionnalité',fontsize=32,fontweight ='bold')
fig_dom_name = plt.xlabel('Fonctionnalités', fontsize = 23,fontweight ='bold')
fig_dom_name = plt.ylabel('Nombre de noms de domaine résolus', fontsize = 23,fontweight ='bold')
fig_dom_name = plt.bar(np.arange(len(tot_dom_names)),tot_dom_names,color ='orange', width = 0.4,
        edgecolor ='grey', label ='Total domain names')
fig_dom_name = plt.xticks(np.arange(len(tot_dom_names)),
        ['Chat',"Partage \nd'écran",'Appel vidéo', 'Tableau \n blanc','Enregistrement',"Chat \ndans l'appel",  'Réactions', 'Appel audio'], fontsize = 18)
fig_dom_name = plt.savefig('figs/dns_dom_names.png')

# IP adress requests :

br1 = np.arange(len(tot__ip_a))
br2 = [x + barWidth for x in br1]
br3 = [x + barWidth for x in br2]
br4 = [x + barWidth for x in br3]

fig_qry = plt.figure(figsize=(20,15))
fig_qry = plt.title('Type de requête adresse ip selon la fonctionnalité',fontsize=32,fontweight ='bold')
fig_qry = plt.bar(br1, tot__ip_a, color ='orange', width = barWidth,
        edgecolor ='grey', label ='A')
fig_qry = plt.bar(br2, tot_ip_aaaa, color ='g', width = barWidth,
        edgecolor ='grey', label ='AAAA')
fig_qry = plt.bar(br3, tot_ip_srv, color ='b', width = barWidth,
        edgecolor ='grey', label ='SRV')
fig_qry = plt.bar(br4, tot_ip_https, color ='r', width = barWidth,
        edgecolor ='grey', label ='HTTPS')

fig_qry = plt.xlabel('Fonctionnalités', fontsize = 23,fontweight ='bold')
fig_qry = plt.ylabel('Nombre de requêtes', fontsize = 23,fontweight ='bold')
fig_qry = plt.xticks([r + barWidth for r in range(len(tot_a))],
        ['Chat',"Partage \nd'écran",'Appel vidéo', 'Tableau \n blanc','Enregistrement',"Chat \ndans l'appel",  'Réactions', 'Appel audio'], fontsize = 18)
 
fig_qry = plt.legend(fontsize=20)
fig_qry = plt.savefig('figs/dns_qry.png')

# IP adress version:

br1 = np.arange(len(tot_ipv4))
br2 = [x + barWidth for x in br1]

fig_ipv = plt.figure(figsize=(20,15))
fig_ipv = plt.title('Version IP préférée par Zoom',fontsize=32,fontweight ='bold')
fig_ipv = plt.bar(br1, tot_ipv4, color ='orange', width = 0.4,
        edgecolor ='grey', label ='ipv4')
fig_ipv = plt.bar(br2, tot_ipv6, color ='g', width = 0.4,
        edgecolor ='grey', label ='ipv6')

fig_ipv = plt.xlabel('Fonctionnalités', fontsize = 23,fontweight ='bold')
fig_ipv = plt.ylabel('Nombre de requêtes adresse IP', fontsize = 23,fontweight ='bold')
fig_ipv = plt.xticks(np.arange(len(tot_ipv4)),
        ['Chat',"Partage \nd'écran",'Appel vidéo', 'Tableau \n blanc','Enregistrement',"Chat \ndans l'appel",  'Réactions', 'Appel audio'], fontsize = 18)
 
fig_ipv = plt.legend(fontsize=20)
fig_ipv = plt.savefig('figs/dns_ipv.png')

# Requests :

br1 = np.arange(len(tot_a))
br2 = [x + barWidth for x in br1]
br3 = [x + barWidth for x in br2]
br4 = [x + barWidth for x in br3]

fig_qry = plt.figure(figsize=(20,15))
fig_qry = plt.title('Type de requête selon la fonctionnalité',fontsize=32,fontweight ='bold')
fig_qry = plt.bar(br1, tot_a, color ='orange', width = barWidth,
        edgecolor ='grey', label ='A')
fig_qry = plt.bar(br2, tot_aaaa, color ='g', width = barWidth,
        edgecolor ='grey', label ='AAAA')
fig_qry = plt.bar(br3, tot_srv, color ='b', width = barWidth,
        edgecolor ='grey', label ='SRV')
fig_qry = plt.bar(br4, tot_https, color ='r', width = barWidth,
        edgecolor ='grey', label ='HTTPS')

fig_qry = plt.xlabel('Fonctionnalités', fontsize = 23,fontweight ='bold')
fig_qry = plt.ylabel('Nombre de requêtes', fontsize = 23,fontweight ='bold')
fig_qry = plt.xticks([r + barWidth  for r in range(len(tot_a))],
        ['Chat',"Partage \nd'écran",'Appel vidéo', 'Tableau \n blanc','Enregistrement',"Chat \ndans l'appel",  'Réactions', 'Appel audio'], fontsize = 18)
 
fig_qry = plt.legend(fontsize=20)
fig_qry = plt.savefig('figs/dns_qry.png')
# fig_qry = plt.show()

# STUN
fig_stun =  plt.figure(figsize=(20,15))
fig_stun = plt.title('Total de protocoles STUN selon la fonctionnalité',fontsize=32,fontweight ='bold')
fig_stun = plt.xlabel('Fonctionnalités', fontsize = 23,fontweight ='bold')
fig_stun = plt.ylabel('Nombre de protocoles STUN', fontsize = 23,fontweight ='bold')
fig_stun = plt.bar(np.arange(len(tot_stun)),tot_stun,color ='orange', width = 0.4,
        edgecolor ='grey', label ='Total STUN protocols')
fig_stun = plt.xticks(np.arange(len(tot_stun)),
        ['Chat',"Partage \nd'écran",'Appel vidéo', 'Tableau \n blanc','Enregistrement',"Chat \ndans l'appel",  'Réactions', 'Appel audio'], fontsize = 18)
fig_stun = plt.savefig('figs/stun.png')


# Tot packets per minute
fig_tot_pckts = plt.figure(figsize=(20,15))
fig_tot_pckts = plt.title('Nombre de paquets echangés par minute selon la fonctionnalité',fontsize=38,fontweight ='bold')
fig_tot_pckts = plt.xlabel('Fonctionnalités', fontsize = 23,fontweight ='bold')
fig_tot_pckts = plt.ylabel('Nombre de paquets par minute', fontsize = 23,fontweight ='bold')
fig_tot_pckts = plt.bar(np.arange(len(tot_pckts)),tot_pckts,color ='orange', width = 0.4,
        edgecolor ='grey', label ='Total packets / minute')
fig_tot_pckts = plt.xticks(np.arange(len(tot_pckts)),
        ['Chat',"Partage \nd'écran",'Appel vidéo', 'Tableau \n blanc','Enregistrement',"Chat \ndans l'appel",  'Réactions', 'Appel audio'], fontsize = 18)
fig_tot_pckts = plt.savefig('figs/app_tot_pckts.png')

# Tot volume per minute
fig_tot_pckts = plt.figure(figsize=(20,15))
fig_tot_pckts = plt.title('Volume de données echangées par minute selon la fonctionnalité',fontsize=32,fontweight ='bold')
fig_tot_pckts = plt.xlabel('Fonctionnalités', fontsize = 23,fontweight ='bold')
fig_tot_pckts = plt.ylabel('Volume de donneées [bytes/min]', fontsize = 23,fontweight ='bold')
fig_tot_pckts = plt.bar(np.arange(len(tot_length)),tot_length,color ='orange', width = 0.4,
        edgecolor ='grey', label ='Total bytes')
fig_tot_pckts = plt.xticks(np.arange(len(tot_pckts)),
        ['Chat',"Partage \nd'écran",'Appel vidéo', 'Tableau \n blanc','Enregistrement',"Chat \ndans l'appel",  'Réactions', 'Appel audio'], fontsize = 18)
fig_tot_pckts = plt.savefig('figs/app_volume.png')