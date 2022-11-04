from http.client import OK
import requests
import json
import time
from utils import helperMethods
from sklearn.cluster import AgglomerativeClustering
import scipy.cluster.hierarchy as sch
import matplotlib.pyplot as plt
import numpy as np

input_config = json.loads(open("config.json", "r").read())
# DB config part
username = input_config["db_config"]["username"]
password =  input_config["db_config"]["password"]
time_wait = input_config["db_config"]["time_wait"]
index_name = input_config["db_config"]["index_name"]
# Cluster process part
affinity = input_config["cluster_config"]["affinity"]
linkage = input_config["cluster_config"]["linkage"]
method = input_config["cluster_config"]["method"]
number_of_clusters =  input_config["cluster_config"]["number_of_clusters"]
segment = input_config["cluster_config"]["segment"]
#src_IP = "160.99.13.128"
while True:
    dictPortDestIP = dict()
    r = requests.get(f'http://localhost:9200/{index_name}/_search?size=10000&pretty', auth=(username, password))

    if r.status_code == 200:
        data = json.loads(r.content)
        src_IP = helperMethods.calculateHistogramForSrcIP(data, index_name)
        if 'snort' in index_name:
            for i in range(0,len(data['hits']['hits'])):
                if (data['hits']['hits'][i]['_source']['src_ip'] == src_IP[8] 
                    and 'dst_port' in data['hits']['hits'][i]['_source']):
                    port = data['hits']['hits'][i]['_source']["dst_port"]
                    destIP = data['hits']['hits'][i]['_source']['dst_ip']
                    timeStampForAlert = data['hits']['hits'][i]['_source']['@timestamp']
                    if (port, destIP) in dictPortDestIP.keys():
                        dictPortDestIP[(port,destIP)].append(timeStampForAlert)
                    else:
                        dictPortDestIP.update({(port,destIP) : [timeStampForAlert]})   
        elif 'netflow' in index_name:
            for i in range(0,len(data['hits']['hits'])):
                if (data['hits']['hits'][i]['_source']['src_geoip']['ip'] == src_IP[0] 
                    and 'l4_dst_port' in data['hits']['hits'][i]['_source']['netflow']):
                    port = data['hits']['hits'][i]['_source']['netflow']['l4_dst_port']
                    destIP = data['hits']['hits'][i]['_source']['dst_geoip']['ip']
                    timeStampForAlert = data['hits']['hits'][i]['_source']['@timestamp']

                    if (port, destIP) in dictPortDestIP.keys():
                        dictPortDestIP[(port,destIP)].append(timeStampForAlert)
                    else:
                        dictPortDestIP.update({(port,destIP) : [timeStampForAlert]})           


        sortedDict = helperMethods.SortirajVremena(dictPortDestIP)
        dictForCountedAlerts = helperMethods.V2brojiSegmente(sortedDict, segment)
        print(f"Recnik kljucevi {sortedDict.keys()}")
        arrayForDTW = []
        for key in dictPortDestIP.keys():
            arrayForDTW.append(dictForCountedAlerts[key])


        dissimilarityMatrix = helperMethods.createDissimilarityMatrix(dictForCountedAlerts)
        y_axis = []
        for key in dictForCountedAlerts.keys():
            y_axis.append(sum(dictForCountedAlerts[key]))
        cluster = AgglomerativeClustering(n_clusters=number_of_clusters, affinity=affinity, linkage=linkage)
        clusters = cluster.fit_predict(dissimilarityMatrix)

        print(clusters)

        plt.figure(figsize=(10, 7))  
        plt.title("Dendrograms")
        dendogram = sch.dendrogram(sch.linkage(dissimilarityMatrix, method = method))
        plt.show() 

        dict_dst_cluster_map, list_of_dst_ips = helperMethods.create_dst_ip_cluster_mapping(sortedDict, clusters)
        x_axis = list_of_dst_ips
        list_of_new_objects = []
        for i in range(0,len(data['hits']['hits'])):
            if (data['hits']['hits'][i]['_source']['src_ip'] == src_IP[9] 
            and 'dst_port' in data['hits']['hits'][i]['_source'] 
            and data['hits']['hits'][i]['_source']['dst_ip'] in list_of_dst_ips):
                new_object = {
                    "clusterID" : dict_dst_cluster_map[data['hits']['hits'][i]['_source']['dst_ip']],
                    "dst_ip" : data['hits']['hits'][i]['_source']['dst_ip'],
                    "dst_port" : data['hits']['hits'][i]['_source']['dst_port'],
                    "src_ip" : data['hits']['hits'][i]['_source']['src_ip']
                }
                list_of_new_objects.append(new_object)
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
        ax.set_xticklabels(ax.get_xticks(), rotation = 90)
        

        fig.show()
        print(len(sortedDict.keys()))
        print(len(clusters))



        time.sleep(15*60)
    # helperMethods.createNewIndex("snort-data-diplomski", list_of_new_objects)
    
    