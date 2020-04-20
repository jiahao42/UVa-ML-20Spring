#!/usr/bin/env python3

import networkx as nx
from math import exp
import numpy as np

# see https://networkx.github.io/documentation/stable/reference/algorithms/similarity.html
def edit_distance(G1, G2):
  return nx.graph_edit_distance(G1, G2)
  # return nx.optimize_graph_edit_distance(G1, G2)
  # return nx.optimal_edit_paths(G1, G2)
  # return nx.simrank_similarity_numpy(G1, G2)

def sigmoid(x):
    if x >= 0:
        z = exp(-x)
        ret = 1 / (1 + z)
        return 1.0 if np.isnan(ret) else ret
    else:
        z = exp(x)
        ret = z / (1 + z)
        return -1.0 if np.isnan(ret) else ret


