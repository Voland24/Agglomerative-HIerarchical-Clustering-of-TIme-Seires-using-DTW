from http.client import OK
import requests
import json

#VEC SU SORTIRANI PO VREME OD RANIJIH KA STARIJIM!!!
username = "elastic"
password = "bhu8bhu8"

src_IP = "160.99.13.129"
dictPortSrcIP = dict()
setOfUniqueIPAdress = set()
r = requests.get('http://localhost:9200/snort-2022.07/_search?size=10000&pretty', auth=(username, password))

if r.status_code == 200:
    data = json.loads(r.content)
    for i in range(0,len(data['hits']['hits'])):
        src_ip = data['hits']['hits'][i]['_source']['src_ip']
        if src_ip in dictPortSrcIP.keys():
            dictPortSrcIP[src_ip] += 1
        else:
            dictPortSrcIP.update({(src_ip) : 0})

    print(dictPortSrcIP.keys())
    print(max(dictPortSrcIP, key=dictPortSrcIP.get))
    #print(f"RECNIK {dictPortDestIP}")