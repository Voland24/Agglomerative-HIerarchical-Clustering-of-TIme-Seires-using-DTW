from http.client import OK
import requests
import json
from utils import helperMethods
from sklearn.cluster import AgglomerativeClustering
import scipy.cluster.hierarchy as sch
import matplotlib.pyplot as plt
#VEC SU SORTIRANI PO VREME OD RANIJIH KA STARIJIM!!!
username = "elastic"
password = "bhu8bhu8"

#src_IP = "160.99.13.128"
dictForAllSrcIP = dict()
dictPortDestIP = dict()
listOfDestIP = []
r = requests.get('http://localhost:9200/snort-2022.07/_search?size=10000&pretty', auth=(username, password))

if r.status_code == 200:
    data = json.loads(r.content)
    src_IP_list = helperMethods.calculateHistogramForSrcIP(data)
    count = -1
    for src_IP in src_IP_list:
        count += 1
        for i in range(0,len(data['hits']['hits'])):
            if count in (7,8,9) and data['hits']['hits'][i]['_source']['src_ip'] == src_IP and 'dst_port' in data['hits']['hits'][i]['_source']:
                    port = data['hits']['hits'][i]['_source']["dst_port"]
                    destIP = data['hits']['hits'][i]['_source']['dst_ip']
                    listOfDestIP.append(destIP)
                    timeStampForAlert = data['hits']['hits'][i]['_source']['@timestamp']

                    if (port, destIP) in dictPortDestIP.keys():
                        dictPortDestIP[(port,destIP)].append(timeStampForAlert)
                    else:
                        dictPortDestIP.update({(port,destIP) : [timeStampForAlert]})   

                    dictForAllSrcIP.update({(src_IP) : dictPortDestIP})


    listOfCountedSeg = []
    for dstDictForSrcIP in dictForAllSrcIP.items():
        sortedDict = helperMethods.SortirajVremena(dstDictForSrcIP[1])
        dictForCountedAlerts = helperMethods.V2brojiSegmente(sortedDict)
        listOfCountedSeg.append(dictForCountedAlerts)
    # print(f"Recnik kljucevi {sortedDict.keys()}")
    # arrayForDTW = []
    # for key in dictPortDestIP.keys():
    #     arrayForDTW.append(dictForCountedAlerts[key])


    dissimilarityMatrix = helperMethods.createDissimilarityMatrix(dictForCountedAlerts)

    # plt.figure(figsize=(10, 7))  
    # plt.title("Dendrograms")
    # dendogram = sch.dendrogram(sch.linkage(dissimilarityMatrix, method = 'ward'))
    # plt.show() 

    cluster = AgglomerativeClustering(n_clusters=2, affinity='euclidean', linkage='ward')  
    clusters = cluster.fit_predict(dissimilarityMatrix)

    print(clusters)

    plt.figure(figsize=(10,7))
    plt.scatter()
    