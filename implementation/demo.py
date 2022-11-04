import requests
import json
import random
r_get = requests.get(f"http://localhost:9200/snort-data-diplomski/_search?size=1000&pretty", auth=("elastic", "bhu8bhu8"))

# requests.put(f"http://localhost:9200/snort_data_novo?pretty", auth=("elastic", "bhu8bhu8"))

# r_put = requests.put(f"http://localhost:9200/snort_data_novo/_mapping?pretty",auth=("elastic", "bhu8bhu8"), json={
#             "properties":{
#                 "clusterID" : {"type" : "short"},
#                 "dst_ip" : {
#                     "type" : "text"
#                             },
#                 "src_ip" : {
#                         "type" : "text"
#                             },            
#                 "dst_port" : {
#                     "type" : "text",
#                             },
                                    
#             }
#         })


data = json.loads(r_get.content)

for elem in data['hits']['hits']:
        new_object = {
                    "dst_ip" : elem['_source']['dst_ip'],
                    "dst_port" : elem['_source']['dst_port'],
                    "src_ip" : elem['_source']['src_ip']
                }
        chance = random.randint(1,4)
        if elem['_source']['clusterID'] == 1:
                new_object['clusterID'] = random.randint(3,4) if chance % 2 == 0 else 1     
        else:
                new_object['clusterID'] =  elem['_source']['clusterID']                
        r = requests.post(f"http://localhost:9200/snort_data_novo/_doc", json=new_object, auth=("elastic", "bhu8bhu8"))


