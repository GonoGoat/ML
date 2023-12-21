from getDataset import generateTrainset, generateTestset, generateEvalset
import pandas as pd
from model import getModel, getEvaluatedset, evaluateModel

proportion = 698

trainsetCsvFile ="./datasets/trainset.csv"
testsetCsvFile ="./datasets/testset.csv"
evalsetCsvFile = "./datasets/evalset.csv"
output = "./out/output.csv"

# Generate datasets if necessary
generateTrainset(trainsetCsvFile,0,0)
#generateTestset(testsetCsvFile,proportion)
#generateEvalset(evalsetCsvFile)

# Load trainset
trainset = pd.read_csv("%s_%d.csv" % (trainsetCsvFile[0:-4],proportion))
print('Shape of trainset:', trainset.shape)
print(trainset['isSafe'].value_counts()) # Check proportion of malware/safe
print(trainset.isnull().sum()) # Check if no column is empty

# Load testset
testset = pd.read_csv("%s_%d.csv" % (testsetCsvFile[0:-4],proportion))
print('Shape of testset:', testset.shape)
print(testset['isSafe'].value_counts())
print(testset.isnull().sum())

# Run model
model = getModel(trainset.drop("name",axis=1))

# Predict evalset
evalset = pd.read_csv(evalsetCsvFile)
getEvaluatedset(evalset,output,model)

#evaluateModel(testset)