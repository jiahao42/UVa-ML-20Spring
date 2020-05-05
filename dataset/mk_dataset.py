#!/usr/bin/env python3
# @File: mk_dataset
# @Author: Jiahao Cai
# @Date: 04/02/2020
# @Description: 

import pickle
import os
import angr
from collections import Counter
from binascii import hexlify

def analyze_binary(path):
  p = angr.Project(path, auto_load_libs = False)
  cfg = p.analyses.CFG()
  p.analyses.CompleteCallingConventions(recover_variables = True)
  p.analyses.Identifier()
  return cfg

"""
Operations:
Iop_Shl, Iop_Shr
Iop_Or, Iop_And
Iop_Xor
Iop_Neg, Iop_Abs / Iop_NegF, Iop_AbsF
Iop_Add, Iop_Sub, Iop_Mul, Iop_Div / Iop_AddF, Iop_SubF, Iop_MulF, Iop_DivF
Iop_CmpEQ, Iop_CmpNE, Iop_CmpLE, Iop_CmpLT / ...32/64F
"""
def extract_raw_features(cfg):
  features = {}
  cfgs = {}
  for name, func in cfg.kb.functions.items():
    try:
      constants = list(set(func.code_constants))
    except Exception as e:
      constants = []
    try:
      ops = Counter(func.operations)
    except Exception as e:
      ops = Counter()
    try:
      strs = func.string_references()
      strs = list(map(lambda x: x[1], strs))
      # strs_as_int = []
      # for s in strs:
        # strs_as_int.append(int(hexlify(s), 16))
    except Exception as e:
      strs = []
    try:
      local_runtime_values = func.local_runtime_values
    except Exception as e:
      local_runtime_values = []
    feature = {
        'name': func.name,
        'num_call_sites': len(func.get_call_sites()),
        'size_func': func.size,
        'num_arguments': len(func.arguments) if func.arguments != None else 0,
        'num_blocks': len(list(func.blocks)),
        'constants': constants,
        'num_nodes': func.graph.number_of_nodes(),
        'num_edges': func.graph.number_of_edges(),
        'operations': ops,
        'strings': strs,
        'local_runtime_values': local_runtime_values,
        'graph': func.graph,
    }
    features[func.name] = feature
    cfgs[func.name] = func.graph
  return features

  binary = binary_path.split('/')[-1]
  with open(binary + '.pickle', 'wb') as f:
    pickle.dump(features, f)

base_path = './'

binary_paths = [
    'tar-1.27/src/tar',
    'grep-2.28/src/grep',
    'bash-4.4.18/bash',
    'wget-1.20/src/wget',
    'patch-2.7/src/patch',
    'bc-1.07/bc/bc',
    'sed-4.8/sed/sed',
    'nano-4.9.2/src/nano',
    'gzip-1.3.14/gzip',
    # 'custom/a.out'
]

compilers = [
    'gcc',
    'clang',
    'tcc'
]

for compiler in compilers:
  for binary_path in binary_paths:
    print('Compiler:', compiler, '\tBinary:', binary_path)
    binary_name = binary_path.split('/')[-1]
    pickle_name = compiler + '_' + binary_name + '.pickle'
    if os.path.exists(pickle_name):
      with open(pickle_name, 'rb') as f:
        fts = pickle.load(f)
    else:
      path = base_path + compiler + '_' + binary_path
      cfg = analyze_binary(path)
      fts = extract_raw_features(cfg)
      with open(pickle_name, 'wb') as f:
        pickle.dump(fts, f)

    # g1 = fts['func1']['graph']
    # g2 = fts['func']['graph']
    # g3 = fts['main']['graph']

    # print(g1.number_of_nodes(), g1.number_of_edges())
    # print(g2.number_of_nodes(), g2.number_of_edges())
    # print(g3.number_of_nodes(), g3.number_of_edges())

  # print(edit_distance(g1, g2))
  # print(edit_distance(g2, g3))
  # print(edit_distance(g1, g3))
  # for i in range(10):
    # print(fts[i]['name'], fts[i+1]['name'], graph.edit_distance(fts[i]['graph'], fts[i+1]['graph']) 


