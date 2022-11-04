
from array import array
import requests
import datetime
import math
import json
import numpy as np
from numpy import array, zeros, full, argmin, inf, ndim
from scipy.spatial.distance import cdist
from math import isinf
username = "elastic"
password = "bhu8bhu8"
def calculateHistogramForSrcIP(data, index_name):
    dictPortSrcIP = dict()
    if 'snort' in index_name:
        for i in range(0,len(data['hits']['hits'])):
            src_ip = data['hits']['hits'][i]['_source']['src_ip']
            if src_ip in dictPortSrcIP.keys():
                dictPortSrcIP[src_ip] += 1
            else:
                dictPortSrcIP.update({(src_ip) : 0})
    else:
        for i in range(0,len(data['hits']['hits'])):
            src_ip = data['hits']['hits'][i]['_source']['src_geoip']['ip']
            if src_ip in dictPortSrcIP.keys():
                dictPortSrcIP[src_ip] += 1
            else:
                dictPortSrcIP.update({(src_ip) : 0})                
    sortedIPs = dict(sorted(dictPortSrcIP.items(), key = lambda item:item[1], reverse=True))
    return list(sortedIPs.keys())[:10]


def SplitujVreme(vreme):
    datum = vreme.split('T')
    godina, mesec, dan = datum[0].split('-')
    sati, minuti, sekunde = datum[1].split(':')
    sekunde, milisekunde = sekunde.split('.')
    milisekunde = milisekunde.split('Z')
    val = datetime.datetime(int(godina),int(mesec),int(dan),int(sati),int(minuti),int(sekunde),int(milisekunde[0]))

    return val    

def SortirajVremena(dictPortDestIP):
    for kljuc in dictPortDestIP.keys():
        n = len(dictPortDestIP[kljuc])
        for i in range(n-1):
            for j in range(0,n-i-1):
                if (dictPortDestIP[kljuc][j] != '0'
                     and dictPortDestIP[kljuc][j+1] != '0'):
                    if (SplitujVreme(dictPortDestIP[kljuc][j]) 
                        < SplitujVreme(dictPortDestIP[kljuc][j+1])):
                        dictPortDestIP[kljuc][j],dictPortDestIP[kljuc][j+1] = \
                         dictPortDestIP[kljuc][j+1],dictPortDestIP[kljuc][j]

    return dictPortDestIP

def V2brojiSegmente(sortiraniRecnik, segment = 50):
    # segment = 50
    recnikSaBrojemAlerta = {}
    for kljuc in sortiraniRecnik.keys():
        recnikSaBrojemAlerta[kljuc] = []
        ind = 0
        for _ in range(0,segment):
            if not ind <= (len(sortiraniRecnik[kljuc])-1):
                recnikSaBrojemAlerta[kljuc].append(0)
                continue
            if sortiraniRecnik[kljuc][ind] == "0":
                ind+=1
                continue
            trenBrojAlerta = 1
            pocetnoVreme = SplitujVreme(sortiraniRecnik[kljuc][ind])
            while ((ind <= len(sortiraniRecnik[kljuc])-1 
            and sortiraniRecnik[kljuc][ind] != "0") 
            and (pocetnoVreme - \
             SplitujVreme(sortiraniRecnik[kljuc][ind])).microseconds <= segment):
                trenBrojAlerta += 1
                ind += 1
            recnikSaBrojemAlerta[kljuc].append(trenBrojAlerta)    
    return recnikSaBrojemAlerta


def LB_Keogh(s1,s2,r):
    LB_sum=0
    for ind,i in enumerate(s1):

        lower_bound=min(s2[(ind-r if ind-r>=0 else 0):(ind+r)])
        upper_bound=max(s2[(ind-r if ind-r>=0 else 0):(ind+r)])

        if i>upper_bound:
            LB_sum=LB_sum+(i-upper_bound)**2
        elif i<lower_bound:
            LB_sum=LB_sum+(i-lower_bound)**2

    return math.sqrt(LB_sum)


def DTWDistance(s1, s2,w):
    DTW={}

    w = max(w, abs(len(s1)-len(s2)))

    for i in range(-1,len(s1)):
        for j in range(-1,len(s2)):
            DTW[(i, j)] = float('inf')
    DTW[(-1, -1)] = 0

    for i in range(len(s1)):
        for j in range(max(0, i-w), min(len(s2), i+w)):
            dist= (s1[i]-s2[j])**2
            DTW[(i, j)] = dist + min(DTW[(i-1, j)],DTW[(i, j-1)], DTW[(i-1, j-1)])

    return math.sqrt(DTW[len(s1)-1, len(s2)-1])


def createDissimilarityMatrix(sortedDictArray):
    disMatrix = []
    manhattan_dist = lambda a,b: np.abs(a-b)
    for kljucPrvi in sortedDictArray.keys():
        for kljucDrugi in sortedDictArray.keys():
            d = dtw(sortedDictArray[kljucPrvi],sortedDictArray[kljucDrugi], dist = manhattan_dist)
            disMatrix.append(d)

    return np.array(disMatrix).reshape(len(sortedDictArray), len(sortedDictArray))


def createNewIndex(index_name, data):
    r_get = requests.get(f"http://localhost:9200/{index_name}/_search?size=10000&pretty", auth=(username, password))
    if r_get.status_code in [404,401]:
        r = requests.put(f"http://localhost:9200/{index_name}?pretty", auth=(username, password))
        if r.status_code == 200:
            createMappingForIndex({},index_name)
            print(json.loads(r.content))
    insertDataToIndex(data, index_name)        


def create_dst_ip_cluster_mapping(dict_of_dst_ip, clusters):
    if len(dict_of_dst_ip.keys()) != len(clusters):
        return None

    dict_return = dict()
    list_of_dst_ips = []
    clusters = clusters.tolist()
    for i,dst_ip in enumerate(dict_of_dst_ip.keys()):
        dict_return.update({(dst_ip[1]):clusters[i]})
        list_of_dst_ips.append(dst_ip[1])

    return dict_return, list_of_dst_ips    


def updateIndex(index_name, data):
    r = requests.put(f"http://localhost:9200/{index_name}/_bulk", json=data, auth=(username, password))
    print(json.loads(r.content))
    return r.status_code == 200

def createMappingForIndex(json_mapping, index_name):
   r_put = requests.put(f"http://localhost:9200/{index_name}/_mapping?pretty",auth=(username, password), json={
            "properties":{
                "clusterID" : {"type" : "short"},
                "dst_ip" : {
                    "type" : "text"
                            },
                "src_ip" : {
                        "type" : "text"
                            },            
                "dst_port" : {
                    "type" : "text",
                            },
                                    
            }
        })
            

def insertDataToIndex(data, index_name):
        for elem in data:
            r = requests.post(f"http://localhost:9200/{index_name}/_doc", json=elem, auth=(username, password))



def _traceback(D):
    i, j = array(D.shape) - 2
    p, q = [i], [j]
    while (i > 0) or (j > 0):
        tb = argmin((D[i, j], D[i, j + 1], D[i + 1, j]))
        if tb == 0:
            i -= 1
            j -= 1
        elif tb == 1:
            i -= 1
        else:  # (tb == 2):
            j -= 1
        p.insert(0, i)
        q.insert(0, j)
    return array(p), array(q)


def dtw(x, y, dist, warp=1, w=inf, s=1.0):
    assert len(x)
    assert len(y)
    assert isinf(w) or (w >= abs(len(x) - len(y)))
    assert s > 0
    r, c = len(x), len(y)
    if not isinf(w):
        D0 = full((r + 1, c + 1), inf)
        for i in range(1, r + 1):
            D0[i, max(1, i - w):min(c + 1, i + w + 1)] = 0
        D0[0, 0] = 0
    else:
        D0 = zeros((r + 1, c + 1))
        D0[0, 1:] = inf
        D0[1:, 0] = inf
    D1 = D0[1:, 1:]  # view
    for i in range(r):
        for j in range(c):
            if (isinf(w) or (max(0, i - w) <= j <= min(c, i + w))):
                D1[i, j] = dist(x[i], y[j])
    C = D1.copy()
    jrange = range(c)
    for i in range(r):
        if not isinf(w):
            jrange = range(max(0, i - w), min(c, i + w + 1))
        for j in jrange:
            min_list = [D0[i, j]]
            for k in range(1, warp + 1):
                i_k = min(i + k, r)
                j_k = min(j + k, c)
                min_list += [D0[i_k, j] * s, D0[i, j_k] * s]
            D1[i, j] += min(min_list)
    if len(x) == 1:
        path = zeros(len(y)), range(len(y))
    elif len(y) == 1:
        path = range(len(x)), zeros(len(x))
    else:
        path = _traceback(D0)
    return D1[-1, -1], C, D1, path

    """
    Computes Dynamic Time Warping (DTW) of two sequences.

    :param array x: N1*M array
    :param array y: N2*M array
    :param func dist: distance used as cost measure
    :param int warp: how many shifts are computed.
    :param int w: window size limiting the maximal distance between indices of matched entries |i,j|.
    :param float s: weight applied on off-diagonal moves of the path. As s gets larger, the warping path is increasingly biased towards the diagonal
    Returns the minimum distance, the cost matrix, the accumulated cost matrix, and the wrap path.
    """