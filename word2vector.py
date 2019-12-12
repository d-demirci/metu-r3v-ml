from gensim.models import word2vec
from bin2op import parse, unique, counts, nextIndex
import numpy as np
import math
import sys
np.set_printoptions(threshold=sys.maxsize)

file =sys.argv[1]
syntax = "intel"

shellcode, code, opcodes, operands, instructions = parse(file, syntax, None)

sentences = instructions
ops = unique(operands + opcodes)
ops.sort()
unique_ops_count = len(ops)

for i, sentence in enumerate(sentences):
	tokenized= []
	for word in sentence.split(' '):
		word = word.split('.')[0]
		word = word.lower()
		tokenized.append(word)
	sentences[i] = tokenized

model = word2vec.Word2Vec(sentences, workers = 1, size = 2, min_count = 1, window = 3, sg = 0)
similar_word = model.wv.most_similar('add')[0]
print("Most common word to add is: {}".format(similar_word[0]))
