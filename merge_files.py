import os 
import pickle
import argparse

max_sentences = 6000000
cur_sentences_count = 0
parser = argparse.ArgumentParser()
parser.add_argument('-d', '--directory')
parser.add_argument('-f', '--file')
args = parser.parse_args()

if args.directory:
    directory = args.directory
else:
    print('need a directory parameter exited')
    sys.exit(0)

if args.file:
    p_file = args.file
else:
    print('need a file parameter exited')
    sys.exit(0)

with open(p_file, 'w') as all_asms:
  for file in os.listdir(directory):
    if cur_sentences_count >= max_sentences:
          break
    with open(os.path.join(directory,file), 'rb') as filehandle:
      sentences = pickle.load(filehandle,encoding='utf8')
      for sentence in sentences:
        cur_sentences_count += 1
        if cur_sentences_count >= max_sentences:
          break
        else:
          all_asms.write(sentence +"; 0" +'\n')