#!/usr/bin/env python3
# @File: utils
# @Author: Jiahao Cai
# @Date: 04/02/2020
# @Description: 

import networkx as nx
# import graphsim as gs
from ged4py.algorithm import graph_edit_dist
from math import exp
import numpy as np
import pickle

# see https://networkx.github.io/documentation/stable/reference/algorithms/similarity.html
def edit_distance(G1, G2):
  # res = nx.graph_edit_distance(G1, G2)
  # res = nx.optimize_graph_edit_distance(G1, G2)
  res = graph_edit_dist.compare(G1, G2)
  print(res)
  return res
  # for v in res:
    # print(v)
    # return v
  # return nx.optimal_edit_paths(G1, G2)
  # return nx.simrank_similarity_numpy(G1, G2)

def sigmoid(x, base = 1.0):
    if x >= 0:
        z = exp(-x)
        ret = 1 / (1 + z)
        return base if np.isnan(ret) else ret * base
    else:
        z = exp(x)
        ret = z / (1 + z)
        return -base if np.isnan(ret) else ret * base

def load_data(data_files, path = 'dataset/'):
  data = []
  for filenames in data_files:
    _data = []
    for filename in filenames:
      with open(path + filename, 'rb') as f:
        _data.append(pickle.load(f))
    data.append(_data)
  return data
