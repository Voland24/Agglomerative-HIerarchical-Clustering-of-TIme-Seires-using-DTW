from http.client import OK
import requests
import json
import time
from utils import helperMethods
from sklearn.cluster import AgglomerativeClustering
import scipy.cluster.hierarchy as sch
import matplotlib.pyplot as plt
import numpy as np
#VEC SU SORTIRANI PO VREME OD RANIJIH KA STARIJIM!!!
username = "elastic"
password = "bhu8bhu8"
number_of_clusters = 2
#src_IP = "160.99.13.128"
while True:
    dictForAllSrcIP = dict()
    dictPortDestIP = dict()
    listOfDestIP = []
    r = requests.get('http://localhost:9200/snort-2022.07/_search?size=10000&pretty', auth=(username, password))

    if r.status_code == 200:
        data = json.loads(r.content)
        src_IP = helperMethods.calculateHistogramForSrcIP(data)
        for i in range(0,len(data['hits']['hits'])):
            if data['hits']['hits'][i]['_source']['src_ip'] == src_IP[9] and 'dst_port' in data['hits']['hits'][i]['_source']:
                port = data['hits']['hits'][i]['_source']["dst_port"]
                destIP = data['hits']['hits'][i]['_source']['dst_ip']
                listOfDestIP.append(destIP)
                timeStampForAlert = data['hits']['hits'][i]['_source']['@timestamp']

                if (port, destIP) in dictPortDestIP.keys():
                    dictPortDestIP[(port,destIP)].append(timeStampForAlert)
                else:
                    dictPortDestIP.update({(port,destIP) : [timeStampForAlert]})   


        sortedDict = helperMethods.SortirajVremena(dictPortDestIP)
        dictForCountedAlerts = helperMethods.V2brojiSegmente(sortedDict)
        print(f"Recnik kljucevi {sortedDict.keys()}")
        arrayForDTW = []
        for key in dictPortDestIP.keys():
            arrayForDTW.append(dictForCountedAlerts[key])


        dissimilarityMatrix = helperMethods.createDissimilarityMatrix(dictForCountedAlerts)
        y_axis = []
        for key in dictForCountedAlerts.keys():
            y_axis.append(sum(dictForCountedAlerts[key]))
        cluster = AgglomerativeClustering(n_clusters=2, affinity='euclidean', linkage='ward')
        clusters = cluster.fit_predict(dissimilarityMatrix)

        print(clusters)

        plt.figure(figsize=(10, 7))  
        plt.title("Dendrograms")
        dendogram = sch.dendrogram(sch.linkage(dissimilarityMatrix, method = 'ward'))
        plt.show() 

        dict_dst_cluster_map, list_of_dst_ips = helperMethods.create_dst_ip_cluster_mapping(sortedDict, clusters)
        x_axis = list_of_dst_ips
        list_of_new_objects = []
        for i in range(0,len(data['hits']['hits'])):
            if data['hits']['hits'][i]['_source']['src_ip'] == src_IP[9] and 'dst_port' in data['hits']['hits'][i]['_source'] and data['hits']['hits'][i]['_source']['dst_ip'] in list_of_dst_ips:
                new_object = {
                    "clusterID" : dict_dst_cluster_map[data['hits']['hits'][i]['_source']['dst_ip']],
                    # "dst_geoip" : data['hits']['hits'][i]['_source']['dst_geoip'],
                    # "src_geoip" : data['hits']['hits'][i]['_source']['src_geoip'],
                    "dst_ip" : data['hits']['hits'][i]['_source']['dst_ip'],
                    "dst_port" : data['hits']['hits'][i]['_source']['dst_port'],
                    "src_ip" : data['hits']['hits'][i]['_source']['src_ip']
                }
                #    new_object = json.dumps(new_object)
                list_of_new_objects.append(new_object)
                
            
            #    data['hits']['hits'][i]['_clusterID'] = dict_dst_cluster_map[data['hits']['hits'][i]['_source']['dst_ip']]
            else:
                data['hits']['hits'][i]['_clusterID'] = 10   
           

    # if helperMethods.updateIndex("snort-2022.07", data=data['hits']['hits']):
    #     print("Success!")
    # else: print("Booo")    



        x_axis = np.array(x_axis)
        y_axis = np.array(y_axis)
        fig = plt.figure()
        ax = fig.add_subplot(111)
        scatter = ax.scatter(x_axis,y_axis,c=clusters,s=50)
        ax.set_xlabel('x')
        ax.set_ylabel('y')
        

        fig.show()
        print(len(sortedDict.keys()))
        print(len(clusters))



        time.sleep(15*60)
    # helperMethods.createNewIndex("snort-data-diplomski", list_of_new_objects)
    
    