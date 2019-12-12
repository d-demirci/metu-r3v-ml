from gensim.models import word2vec
from bin2op import parse, unique, counts, nextIndex
import numpy as np
import math
import sys, os
import argparse
import pickle
np.set_printoptions(threshold=sys.maxsize)

parser = argparse.ArgumentParser()
parser.add_argument('-d', '--directory')
args = parser.parse_args()

if args.directory:
    directory = args.directory
else:
    print('need a file parameter exited')
    sys.exit(0)

for file in os.listdir(directory):
    syntax = "intel"
    print('file process started > {}'.format(file))
    try:
        shellcode, code, opcodes, operands, instructions = parse(os.path.join(directory,file), syntax, None)

        sentences = instructions
        # ops = unique(operands + opcodes)
        # ops.sort()
        # unique_ops_count = len(ops)

        # for i, sentence in enumerate(sentences):
        #     tokenized= []
        #     for word in sentence.split(' '):
        #         word = word.split('.')[0]
        #         word = word.lower()
        #         tokenized.append(word)
        #     sentences[i] = tokenized

        with open('/mnt/hgfs/VM_SHARED/extracted_asm/'+file, 'wb') as sentences_file:
            pickle.dump(sentences, sentences_file)
            print('file processed > {}'.format(file))
            # model = word2vec.Word2Vec(sentences, workers = 1, size = 2, min_count = 1, window = 3, sg = 0)
            # similar_word = model.wv.most_similar('add')[0]
            # print("Most common word to add is: {}".format(similar_word[0]))
    except Exception as e:
        print('file couldnt be processed > {}'.format(file))
