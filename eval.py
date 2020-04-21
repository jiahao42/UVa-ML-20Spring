#!/usr/bin/env python3
# @File: eval
# @Author: Jiahao Cai
# @Date: 04/21/2020
# @Description: 

from sklearn.metrics.pairwise import cosine_similarity as cos_sim
from sklearn.ensemble import RandomForestClassifier
from core import *

training_data_files = [
  [
    'gcc_grep.pickle',
    'clang_grep.pickle',
    'tcc_grep.pickle',
  ],
  [
    'gcc_bash.pickle',
    'clang_bash.pickle',
    'tcc_bash.pickle',
  ],
  [
    'gcc_tar.pickle',
    'clang_tar.pickle',
    'tcc_tar.pickle',
  ],
]

eval_data_files = [
  [
    'gcc_bc.pickle',
    'clang_bc.pickle',
    'tcc_bc.pickle',
  ],
  # [
    # 'gcc_patch.pickle',
    # 'clang_patch.pickle',
    # 'tcc_patch.pickle',
  # ],
  # [
    # 'gcc_wget.pickle',
    # 'clang_wget.pickle',
    # 'tcc_wget.pickle',
  # ]
]

def get_topN_result(base, paths, N = 5):
  sims = [(cos_sim(path, base), i) for i, path in enumerate(paths)]
  sims = sorted(sims, key = lambda x: x[0], reverse = True)
  return sims[:N]

def eval_one(rfc, target, features):
  res = []
  base, _ = rfc.decision_path([normalize(target) + normalize(target)])
  nfs = [None for _ in range(len(features))]
  for i, (name, f) in enumerate(features.items()):
    nf = normalize(target) + normalize(f)
    nfs[i] = nf
    
  paths, _ = rfc.decision_path(nfs)
  return get_topN_result(base, paths)


def eval_all():
  rfc = RandomForestClassifier(random_state = 42)
  train(rfc, training_data_files)
  eval_data = load_data(eval_data_files)
  for prog_data in eval_data:
    data = [
      [prog_data[0], prog_data[1]],
      [prog_data[0], prog_data[2]],
      [prog_data[1], prog_data[2]],
    ]
    for x, y in data:
      for name, feature in x.items():
        if feature['size_func'] < 12: continue
        if 'sub_' in name: continue
        if name not in y: continue
        res = eval_one(rfc, feature, y)

        print(name)
        for val, i in res:
          print(list(y)[i])
        print('x'*77)


if __name__ == '__main__':
  eval_all()

