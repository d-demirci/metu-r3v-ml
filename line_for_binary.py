import os 
import pickle
import argparse

max_binary_count = 260
cur_binary_count = 0
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
    cur_binary_count += 1
    if cur_binary_count >= max_binary_count:
          break
    with open(os.path.join(directory,file), 'rb') as filehandle:
      lines = pickle.load(filehandle,encoding='utf8')
      all_in_on_line = '. '.join([line.strip() for line in lines])
      all_asms.write(all_in_on_line +'\n')