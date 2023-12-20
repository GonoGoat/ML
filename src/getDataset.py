from os import listdir
from os.path import isfile, join
from getFeatures import getFeatures
import pandas as pd
from numpy import array
from numpy.random import shuffle

def getFilesNameFromDir(dir):
    return  array([f for f in listdir("./heh-cybersecurity-2023-2024/%s" % dir) if isfile(join(("./heh-cybersecurity-2023-2024/%s" % dir), f))])
    
        
def generateTrainset(trainsetFile, malwareQuantity, safeQuantity):
    malware, safe = getFilesNameFromDir("trainset/trainset/malware") , getFilesNameFromDir("trainset/trainset/safe")
    #print(safe[502])

    if (safeQuantity == 0):
        safeIndex = len(safe)
    else:
        safeIndex = safeQuantity
        
    if (malwareQuantity == 0):
        malwareIndex = len(malware)
    else:
        malwareIndex = malwareQuantity
        
    if (malwareIndex > safeIndex):
        index = malwareIndex
    else:
        index = safeIndex
    
    dataset = []
    for nbr in range(index):
        if (nbr < malwareIndex):
            dataset.append({"name" : malware[nbr][:-4], "isSafe" : 0} | getFeatures("./heh-cybersecurity-2023-2024/trainset/trainset/malware/%s" % malware[nbr]))
            print("Malware : %d/%d" % (nbr, malwareIndex))
        if (nbr < safeIndex):
            dataset.append({"name" : safe[nbr][:-4], "isSafe" : 1} | getFeatures("./heh-cybersecurity-2023-2024/trainset/trainset/safe/%s" % safe[nbr]))
            print("Safe : %d/%d" % (nbr,safeIndex))
    df = pd.DataFrame.from_dict(dataset)
    df.to_csv("%s_%d_%d.csv" % (trainsetFile[0:-4],malwareQuantity,safeQuantity)  , index=False, header=True)
    
def generateTestset(testsetFile):
    dataset = getFilesNameFromDir("testset/testset")
    testset = []
    for index, exe in enumerate(dataset):
        testset.append({"name" : exe[:-4]} | getFeatures("./heh-cybersecurity-2023-2024/testset/testset/%s" % exe))
        print("%d/%d" % (index,len(dataset)))
    
    df = pd.DataFrame.from_dict(testset) 
    df.to_csv(testsetFile, index=False, header=True)
    
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