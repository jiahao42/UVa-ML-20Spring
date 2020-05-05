#!/usr/bin/env python3
# @File: show
# @Author: Jiahao Cai
# @Date: 05/03/2020
# @Description: 

import sys


with open(sys.argv[1], 'r') as f:
  lines = f.read().split('\n')[:-4]

s = 0.0
r = 0.0

for line in lines:
  if line == '': continue
  target, cands = line.split(' ', 1)
  cands = cands.split(',')
  try:
    idx = cands.index(target)
  except ValueError as e:
    idx = 100
  s += idx + 1
  r += 1

print(s, r, s / r)


