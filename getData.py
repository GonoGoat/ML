from os import listdir
from os.path import isfile, join
from random import shuffle

def getFilesNameFromDir(dir):
    return [f for f in listdir("./heh-cybersecurity-2023-2024/%s" % dir) if isfile(join(("./heh-cybersecurity-2023-2024/%s" % dir), f))]
    
        
def importDataset():
    return shuffle(getFilesNameFromDir("trainset/trainset/malware") + getFilesNameFromDir("trainset/trainset/safe"))