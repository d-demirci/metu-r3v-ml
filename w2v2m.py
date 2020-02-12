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
    print('need a directory parameter exited')
    sys.exit(0)

for file in os.listdir(directory):
    syntax = "intel"
    print('file process started > {}'.format(file))
    try:
        shellcode, code, opcodes, operands, instructions = parse(os.path.join(directory,file), syntax, None)

        sentences = instructions

        with open('/mnt/hgfs/benign/'+file+'.asm', 'wb') as sentences_file:
            pickle.dump(sentences, sentences_file)
            print('file processed > {}'.format(file))
    except Exception as e:
        print('file couldnt be processed > {} {} '.format(file, str(e)))
