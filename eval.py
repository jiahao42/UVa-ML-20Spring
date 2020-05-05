#!/usr/bin/env python3
# @File: eval
# @Author: Jiahao Cai
# @Date: 04/21/2020
# @Description: 

from sklearn.metrics.pairwise import cosine_similarity as cos_sim
from sklearn.metrics import jaccard_score
from sklearn.metrics.pairwise import euclidean_distances
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import RandomForestRegressor
from sklearn.linear_model import Ridge
from sklearn.svm import SVC
from core import *


def get_topN_result(sims, N):
  sims = sorted(sims, key = lambda x: x[0], reverse = True)
  # sims = sorted(sims, key = lambda x: x[0], reverse = False)
  return sims[:N]

def similarity(x, y):
  return cos_sim(x, y)

def random_forest_classifier_eval(trainer, target, features):
  base, _ = trainer.decision_path([target])
  paths, _ = trainer.decision_path(features)
  res = [(similarity(path, base), i) for i, path in enumerate(paths)]
  return res

def general_predict(trainer, target, features):
  res = trainer.predict(features)
  res = [(val, i) for i, val in enumerate(res)]
  # print(res)
  return res

def cosine_eval(trainer, target, features):
  return [(cos_sim([target], [f]), i) for i, f in enumerate(features)]

random_forest_regressor_eval = general_predict
SVC_eval = general_predict
ridge_eval = general_predict

"""Configuration"""
rfc = RandomForestClassifier(random_state = 42, n_estimators = 500)
rfr = RandomForestRegressor(random_state = 42)
svc = SVC(gamma='auto')
ridge = Ridge(alpha = 1.0)
trainer = rfc

eval_func = random_forest_classifier_eval

def graph_eval(scores, target, features):
  G1 = target['graph']
  fl = list(features.values())
  for score, i in scores:
    f = fl[i]
    G2 = f['graph']
    score = sigmoid(scores[i][0])
    dist = sigmoid(edit_distance(G1, G2))
    # print(score, dist)
    scores[i] = (score - dist, scores[i][1])
  return scores

def eval_one(trainer, target, features, N = 5):
  """Return: index of similar functions"""
  res = []
  target_nf = normalize(target) + normalize(target)
  nfs = [None for _ in range(len(features))]
  for i, (name, f) in enumerate(features.items()):
    nf = normalize(f) + normalize(f)
    nfs[i] = nf
  scores = eval_func(trainer, target_nf, nfs) # [(score, index)]
  scores = graph_eval(scores, target, features)
  return get_topN_result(scores, N)


def eval_all(training_data_files, eval_data_files, eval_prog):
  train_features, train_labels = prepare_training_data(training_data_files)
  trainer.fit(train_features, train_labels)
  print(eval_data_files)
  eval_data = load_data(eval_data_files)
  eval_data = preprocess(eval_data)
  for prog_data in eval_data:
    data = [
      ['gcc_clang', prog_data[0], prog_data[1]], # gcc, clang
      ['gcc_tcc', prog_data[0], prog_data[2]], # gcc, tcc
      ['clang_tcc', prog_data[1], prog_data[2]], # clang, tcc
    ]
    buf = ''
    total_count = 0
    topN_corr_count = 0
    exact_corr_count = 0
    for compiler_comb, x, y in data: 
      yl = list(y)
      for name, feature in x.items():
        if name == 'main': continue # for now
        if name not in y: continue # name only appears in one program
        nf = [normalize(feature) + normalize(feature)]
        if nf.count(0) / len(nf) > 0.5: continue # discard if the feature has too many 0
        total_count += 1 
        numerical_topN = 100
        res = eval_one(trainer, feature, y, numerical_topN)
        names = [yl[i] for val, i in res]
        if names[0] == name:
          exact_corr_count += 1
        if name in names:
          topN_corr_count += 1
        line = name + ' ' + ','.join(names)
        buf += line + '\n'
        print(line)
    with open(f'{compiler_comb}_{eval_prog}.txt', 'w') as f:
      f.write(buf)
      f.write(f'{exact_corr_count}, {topN_corr_count}, {total_count}\n')
      f.write(f'{exact_corr_count / total_count}\n')
      f.write(f'{topN_corr_count / total_count}\n')

compilers = ['gcc', 'clang', 'tcc']
programs = [
  'grep', 
  'bash', 
  'tar', 
  'patch',
  'wget', 
  'bc', 
  'sed', 
  'nano', 
  'gzip',
]
if __name__ == '__main__':
  for prog in programs:
    training_programs = programs.copy()
    training_programs.remove(prog)
    training_data_files = [
      [f'{compiler}_{prog}.pickle' for compiler in compilers] for prog in training_programs
    ]
    eval_programs = [prog]
    eval_data_files = [[f'{compiler}_{prog}.pickle' for compiler in compilers] for ep in eval_programs]
    print(f'evaluating {prog}')
    # print(training_data_files)
    # print(eval_data_files)

    eval_all(training_data_files, eval_data_files, prog)

