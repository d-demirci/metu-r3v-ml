from gensim.models import word2vec as w2v
from bin2op import parse, unique, counts, nextIndex
import numpy as np
import math
import sys
np.set_printoptions(threshold=sys.maxsize)
from matplotlib import pyplot

# https://stackoverflow.com/questions/55188209/use-word2vec-to-determine-which-two-words-in-a-group-of-words-is-most-similar

from sklearn.decomposition import PCA
from matplotlib import pyplot

file = './a.exe'
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

# using CBOW
model = w2v.Word2Vec(sentences, workers = 1, size = 2, min_count = 1, window = 3, sg = 0)

# https://machinelearningmastery.com/develop-word-embeddings-python-gensim/


X = model[model.wv.vocab]
#creating a 2-dimensional Principal Component Analysis model
pca = PCA(n_components=2)
result = pca.fit_transform(X)
# create a scatter plot of the projection
pyplot.scatter(result[:, 0], result[:, 1])
words = list(model.wv.vocab)
words = words[0:20]
for i, word in enumerate(words):
	pyplot.annotate(word, xy=(result[i, 0], result[i, 1]))
pyplot.savefig('foo5.pdf')