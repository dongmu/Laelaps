import logging
import sys
import os
import shutil

LOGDIR = 'logfiles'
if os.path.exists(LOGDIR):
	shutil.rmtree(LOGDIR)
os.makedirs(LOGDIR)


logger = logging.getLogger(__name__)

logger.setLevel(logging.DEBUG)

# propagate to Angr for STDIO
# ch = logging.StreamHandler(sys.stdout)
# logger.addHandler(ch)

# we handle fh
fh = logging.FileHandler(filename="./logfiles/laelaps.txt",mode='w')
logger.addHandler(fh)


formatter = logging.Formatter('%(asctime)s | %(name)s | %(levelname)s - %(message)s')
fh.setFormatter(formatter)


# well let STDIO handled in Angr for now
# logger.propagate = False
