#!/usr/bin/env python3
# @File: eval
# @Author: Jiahao Cai
# @Date: 04/21/2020
# @Description: 

from sklearn.metrics.pairwise import cosine_similarity as cos_sim
from sklearn.ensemble import RandomForestClassifier
from core import *

programs = [
  'grep', 'bash', 'tar', 'patch',
  'wget', 'patch', 'bc', 'sed',
  'nano', 'gzip',
]
compilers = ['gcc', 'clang', 'tcc']
training_data_files = [
  [f'{compiler}_{prog}.pickle' for compiler in compilers] for prog in programs
]

eval_programs = ['bc']
eval_data_files = [
  [f'{compiler}_{prog}.pickle' for compiler in compilers] for prog in eval_programs
]

def get_topN_result(base, paths, N):
  sims = [(cos_sim(path, base), i) for i, path in enumerate(paths)]
  sims = sorted(sims, key = lambda x: x[0], reverse = True)
  return sims[:N]

def eval_one(rfc, target, features, N = 5):
  """Return: index of similar functions"""
  res = []
  base, _ = rfc.decision_path([normalize(target) + normalize(target)])
  nfs = [None for _ in range(len(features))]
  for i, (name, f) in enumerate(features.items()):
    # nf = normalize(target) + normalize(f)
    nf = normalize(f) + normalize(f)
    nfs[i] = nf
    
  paths, _ = rfc.decision_path(nfs)
  return get_topN_result(base, paths, N)

def eval_all():
  rfc = RandomForestClassifier(random_state = 42, n_estimators = 200)
  train(rfc, training_data_files)
  eval_data = load_data(eval_data_files)
  eval_data = preprocess(eval_data)
  total_count = 0
  topN_corr_count = 0
  exact_corr_count = 0
  for prog_data in eval_data:
    data = [
      [prog_data[0], prog_data[1]],
      [prog_data[0], prog_data[2]],
      [prog_data[1], prog_data[2]],
    ]
    for x, y in data: 
      yl = list(y)
      for name, feature in x.items():
        # if feature['size_func'] < 4: continue
        # if 'sub_' in name: continue
        if name not in y: continue
        total_count += 1 
        res = eval_one(rfc, feature, y, 5)
        names = [yl[i] for val, i in res]
        G1 = feature['graph']
        Gsims = []
        for name in names:
          G2 = y[name]['graph']
          dist = edit_distance(G1, G2)
          Gsims.append((dist, name))
        Gsims = sorted(Gsims, key=lambda x: x[0], reverse = True)
        topN = Gsims[:5]
        names = [name for sim, name in topN]
        print(name, names)
        if names[0] == name:
          exact_corr_count += 1
        if name in names:
          topN_corr_count += 1
        # print(name, names)
  print(exact_corr_count, topN_corr_count, total_count)
  print(exact_corr_count / total_count)
  print(topN_corr_count / total_count)

if __name__ == '__main__':
  eval_all()

