#!/usr/bin/env python3

import networkx as nx

# see https://networkx.github.io/documentation/stable/reference/algorithms/similarity.html
def edit_distance(G1, G2):
  return nx.graph_edit_distance(G1, G2)
  # return nx.optimize_graph_edit_distance(G1, G2)
  # return nx.optimal_edit_paths(G1, G2)
  # return nx.simrank_similarity_numpy(G1, G2)


