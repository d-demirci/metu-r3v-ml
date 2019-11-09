from sklearn.feature_extraction.text import HashingVectorizer
from bin2op import parse, unique, counts, nextIndex
import numpy as np
import math
import sys
np.set_printoptions(threshold=sys.maxsize)

file = './a.exe'
syntax = "intel"
shellcode, code, opcodes, operands, instructions = parse(file, syntax, None)

sentences = instructions
ops = unique(operands + opcodes)
ops.sort()
unique_ops_count = len(ops)

vectorizer = HashingVectorizer(norm = None, n_features = unique_ops_count)
sentence_vectors = vectorizer.fit_transform(sentences)
vector2array= sentence_vectors.toarray()
arr = np.array(vector2array)
print(arr[0:3])
