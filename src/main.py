from getDataset import generateTrainset, generateTestset, generateEvalset
import pandas as pd
from sklearn import tree
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from model import getModel, getEvaluatedset

safeQuantity = 500
malwareQuantity = 1000

trainsetCsvFile ="./datasets/trainset.csv"
testsetCsvFile ="./datasets/testset.csv"
evalsetCsvFile = "./datasets/evalset.csv"
output = "./out/output.csv"

# Generate datasets if necessary
#generateTrainset(trainsetCsvFile,malwareQuantity, safeQuantity)
#generateTestset(testsetCsvFile)
#generateEvalset(evalsetCsvFile)

# Load trainset
trainset = pd.read_csv("%s_%d_%d.csv" % (trainsetCsvFile[0:-4],malwareQuantity,safeQuantity))
evalset = pd.read_csv(evalsetCsvFile)

print('Shape of dataframe:', trainset.shape)
trainset.head()

# Check propportion of malware/safe
print(trainset['isSafe'].value_counts())

# Check if no column is empty
print(trainset.isnull().sum())

# Run model
model = getModel(trainset.drop("name",axis=1))

# Predict evalset
getEvaluatedset(evalset,output,model)