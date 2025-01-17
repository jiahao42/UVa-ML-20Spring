#!/usr/bin/env python3
# @File: core
# @Author: Jiahao Cai
# @Date: 04/21/2020
# @Description: 


from sklearn.metrics.pairwise import cosine_similarity as cos_sim
from sklearn.ensemble import RandomForestClassifier
import pickle
from utils import *
import random
from collections import Counter, OrderedDict
import binascii
from decimal import Decimal

def prepare_pos(data1, data2):
  features = []
  names = []
  for name, feature in data1.items():
    f1 = feature
    if name not in data2: continue
    f2 = data2[name]
    features.append(normalize(f1) + normalize(f2))
    names.append(name)
  return features, [1] * len(features), names

def prepare_neg(pos, neg):
  features = []
  names = []
  labels = []
  names = list(pos.keys())
  fs = list(pos.values())
  for i, (name, feature) in enumerate(zip(names, fs)):
    f1 = feature
    f2 = fs[(i + 1) % len(pos)]
    # f2 = neg[i]
    # max_sz = max(f1['size_func'], f2['size_func'])
    # min_sz = min(f1['size_func'], f2['size_func'])
    # if min_sz == 0:
      # label = 0.0
    # else:
      # label = max_sz / min_sz
    # labels.append(label)
    features.append(normalize(f1) + normalize(f2))
    names.append(name)
  labels = [0] * len(pos)
  return features, labels, names

op_list = [
  ['Shl', 'Shr'],
  ['Or'], 
  ['And'],
  ['Xor'],
  ['NegF', 'AbsF'],
  ['Neg', 'Abs'],
  ['AddF', 'SubF', 'MulF', 'DivF'],
  ['Add', 'Sub', 'Mul', 'Div'],
  ['CmpEQ32F', 'CmpEQ64F', 'CmpNE'],
  ['CmpLE32F', 'CmpLE64F'],
  ['CmpLT32F', 'CmpLT64F'], 
  ['CmpGE32F', 'CmpGE64F'], 
  ['CmpGT32F', 'CmpGT64F'],
  ['CmpEQ', 'CmpNE'], 
  ['CmpLE', 'CmpLT'], 
  ['CmpGE', 'CmpGT'],
]

CONSTANT_MAX_NUM = 200
STRING_MAX_NUM = 200

def normalize(f):
  # features = []
  # for f in [f1, f2]:
  feature = []
  for name, data in f.items():
    if name == 'constants':
      constants = list(map(lambda x: sigmoid(x, 10.0), list(data)))
      # constants = list(data)
      if len(constants) < CONSTANT_MAX_NUM:
        constants += [0] * (CONSTANT_MAX_NUM - len(constants))
      # constants.sort(reverse = True)
      feature += constants[:CONSTANT_MAX_NUM]
    elif name == 'strings':
      strs = []
      for x in data:
        while len(x) > 10:
          strs.append(x[:10])
          x = x[10:]
      strs = list(map(lambda x: int(binascii.hexlify(bytearray(x, encoding='utf-8')), 16), strs))
      if len(data) < STRING_MAX_NUM:
        strs += [0] * (STRING_MAX_NUM - len(strs))
      feature += strs[:STRING_MAX_NUM] 
      # print(feature)
    elif name == 'graph' or name == 'name':
      continue
    elif name == 'operations':
      # continue
      f = [0] * len(op_list)
      for target, num in data.items(): # {op: # of appearance}
        found = False
        for i, ops in enumerate(op_list):
          if found: break
          for op in ops:
            if op in target:
              f[i] += 1
              found = True
              break
      feature += f
    elif name == 'local_runtime_values':
      feature += list(f)
    elif isinstance(data, list):
      feature += data
    else:
      feature.append(data)
  return feature

def gen_random_operations():
  op_map = {}
  for ops in op_list:
    op_map[random.choice(ops)] = random.randint(0, 100)
  return op_map

def gen_negative_samples(size):
  samples = [None for _ in range(size)]
  for i in range(size):
    num_call_sites = random.randint(0, 50)
    size_func = random.randint(128, 1024)
    num_arguments = random.randint(0, 20)
    num_constants = random.randint(0, CONSTANT_MAX_NUM)
    constants = [0] * num_constants
    for ii in range(num_constants):
      constants[ii] = random.randint(0, 0xffffffff)
    # constants.sort(reverse = True)
    num_nodes = random.randint(0, 800)
    num_edges = random.randint(0, 1000)
    samples[i] = {
      'num_call_sites': num_call_sites,
      'size_func': size_func,
      'num_arguments': num_arguments,
      'num_constants': num_constants,
      'constants': constants,
      'num_nodes': num_nodes,
      'num_edges': num_edges, 
      'strings': [random.randint(0, 0xffffffffffff) for _ in range(random.randint(0, 10))],
      'operations': gen_random_operations()
    }
  return samples

def preprocess(training_data):
  ntraining_data = []
  for data in training_data:
    ndata = []
    for d in data:
      nd = OrderedDict()
      for name, feature in d.items():
        if feature['size_func'] >= 512 and 'sub_' not in name and len(feature['constants']) >= 10:
          nd[name] = feature
      # print("after preprocessing", len(d), len(nd))
      ndata.append(nd)
    ntraining_data.append(ndata)
  return ntraining_data

def prepare_training_data(training_data_files):
  train_features = []
  train_labels = []
  training_data = load_data(training_data_files)
  training_data = preprocess(training_data)
  for data in training_data:
    gcc_data = data[0]
    clang_data = data[1]
    tcc_data = data[2]
    gcc_neg_data = gen_negative_samples(len(gcc_data) * 10)
    clang_neg_data = gen_negative_samples(len(clang_data) * 10)
    tcc_neg_data = gen_negative_samples(len(tcc_data) * 10)

    gc_pos_features, gc_pos_labels, _ = prepare_pos(gcc_data, clang_data)
    gt_pos_features, gt_pos_labels, _ = prepare_pos(gcc_data, tcc_data)
    ct_pos_features, ct_pos_labels, _ = prepare_pos(clang_data, tcc_data)

    gcc_neg_features, gcc_neg_labels, _ = prepare_neg(gcc_data, gcc_neg_data)
    clang_neg_features, clang_neg_labels, _ = prepare_neg(clang_data, clang_neg_data)
    tcc_neg_features, tcc_neg_labels, _ = prepare_neg(tcc_data, tcc_neg_data)
    train_features += \
      gc_pos_features + \
      gt_pos_features + \
      ct_pos_features + \
      gcc_neg_features + \
      clang_neg_features + \
      tcc_neg_features
    train_labels += \
      gc_pos_labels + \
      gt_pos_labels + \
      ct_pos_labels + \
      gcc_neg_labels + \
      clang_neg_labels + \
      tcc_neg_labels
  return train_features, train_labels


if __name__ == '__main__':
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
  with open('dataset/gcc_bash.pickle', 'rb') as f:
    gcc_bash = pickle.load(f)
  with open('dataset/clang_bash.pickle', 'rb') as f:
    clang_bash = pickle.load(f)
  with open('dataset/tcc_bash.pickle', 'rb') as f:
    tcc_bash = pickle.load(f)
  # grep_clang_tcc_features, grep_clang_tcc_labels, _ = prepare_pos(clang_grep, tcc_grep)
  bash_gcc_clang_features, bash_gcc_clang_labels, bash_gcc_clang_names = prepare_pos(gcc_bash, clang_bash)
  bash_tcc_clang_features, bash_tcc_clang_labels, bash_tcc_clang_names = prepare_pos(tcc_bash, clang_bash)

  rfc = RandomForestClassifier(random_state = 42)
  train_features, train_labels = prepare_training_data(training_data_files)
  rfc.fit(train_features, train_labels)
  paths, _ = rfc.decision_path(bash_gcc_clang_features)

  base, _ = rfc.decision_path([bash_tcc_clang_features[10]])
  sims = [(cos_sim(path, base), i) for i, path in enumerate(paths)]
  sims = sorted(sims, key = lambda x: x[0], reverse = True)
  for sim, i in sims[:3]:
    print(bash_gcc_clang_names[i])
    print(sim)
  for sim, i in sims[-3:]:
    print(bash_gcc_clang_names[i])
    print(sim)
  print(bash_gcc_clang_names[sims[0][1]])
  print(bash_tcc_clang_names[10])

    


