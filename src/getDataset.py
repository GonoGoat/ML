from os import listdir
from os.path import isfile, join
from getFeatures import getFeatures
import pandas as pd

def getFilesNameFromDir(dir):
    return  [f for f in listdir("./heh-cybersecurity-2023-2024/%s" % dir) if isfile(join(("./heh-cybersecurity-2023-2024/%s" % dir), f))]

def generateTrainset(trainsetFile, proportion):
    malware, safe = getFilesNameFromDir("trainset/trainset/malware") , getFilesNameFromDir("trainset/trainset/safe")
    #print(safe[502])

    if (proportion > len(malware) | proportion > len(safe)):
        raise RuntimeError('Too much files asked for training')
    dataset = []
    for nbr in range(proportion):
        dataset.append({"name" : malware[nbr][:-4], "isSafe" : 0} | getFeatures("./heh-cybersecurity-2023-2024/trainset/trainset/malware/%s" % malware[nbr]))
        
        dataset.append({"name" : safe[nbr][:-4], "isSafe" : 1} | getFeatures("./heh-cybersecurity-2023-2024/trainset/trainset/safe/%s" % safe[nbr]))
        print("Trainingset : %d/%d" % (nbr, proportion))
    df = pd.DataFrame.from_dict(dataset)
    df.to_csv("%s_%d.csv" % (trainsetFile[0:-4],proportion)  , index=False, header=True)
    
def generateTestset(testsetFile, proportion):
    malware, safe = getFilesNameFromDir("trainset/trainset/malware") , getFilesNameFromDir("trainset/trainset/safe")
    index = max([len(malware),len(safe)])
    
    testset = []
    for nbr in range(proportion, index):
        if (nbr < len(malware)):
            testset.append({"name" : malware[nbr][:-4], "isSafe" : 0} | getFeatures("./heh-cybersecurity-2023-2024/trainset/trainset/malware/%s" % malware[nbr]))
            print("Malware : %d/%d" % (nbr, index))
        if (nbr < len(safe)):
            testset.append({"name" : safe[nbr][:-4], "isSafe" : 1} | getFeatures("./heh-cybersecurity-2023-2024/trainset/trainset/safe/%s" % safe[nbr]))
            print("Safe : %d/%d" % (nbr,index))
    
    df = pd.DataFrame.from_dict(testset).sample(frac=1)
    df.to_csv("%s_%d.csv" % (testsetFile[0:-4],proportion), index=False, header=True)
    
def generateEvalset(evalsetFile):
    testset = getFilesNameFromDir("testset/testset")
    malware, safe = getFilesNameFromDir("trainset/trainset/malware") , getFilesNameFromDir("trainset/trainset/safe")
    
    index = max([len(testset),len(malware),len(safe)])
    
    evalset = []
    for nbr in range(index):
        if (nbr < len(malware)):
            evalset.append({"name" : int(malware[nbr][:-4])} | getFeatures("./heh-cybersecurity-2023-2024/trainset/trainset/malware/%s" % malware[nbr]))
            print("Malware : %d/%d" % (nbr, len(malware)))
        if (nbr < len(safe)):
            evalset.append({"name" : int(safe[nbr][:-4])} | getFeatures("./heh-cybersecurity-2023-2024/trainset/trainset/safe/%s" % safe[nbr]))
            print("Safe : %d/%d" % (nbr, len(safe)))
            
        if (nbr < len(testset)):
            evalset.append({"name" : int(testset[nbr][:-4])} | getFeatures("./heh-cybersecurity-2023-2024/testset/testset/%s" % testset[nbr]))
            print("Eval : %d/%d" % (nbr,len(testset)))
            
    df = pd.DataFrame.from_dict(evalset).sort_values(by=["name"]) 
    df.to_csv(evalsetFile, index=False, header=True)