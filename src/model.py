# Import libraries
## Basic libs
import pandas as pd
import numpy as np
## Data Visualization
#import seaborn as sns
import matplotlib.pyplot as plt

from sklearn import tree
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier

import sklearn as sk
from sklearn.model_selection import train_test_split

def evaluate_model(model, x_test, y_test):
    # Predict Test Data 
    y_pred = model.predict(x_test)

    # Calculate accuracy, precision, recall, f1-score, and kappa score
    acc = sk.metrics.accuracy_score(y_test, y_pred)
    prec = sk.metrics.precision_score(y_test, y_pred)
    rec = sk.metrics.recall_score(y_test, y_pred)
    f1 = sk.metrics.f1_score(y_test, y_pred)
    kappa = sk.metrics.cohen_kappa_score(y_test, y_pred)

    # Calculate area under curve (AUC)
    y_pred_proba = model.predict_proba(x_test)[::,1]
    fpr, tpr, _ = sk.metrics.roc_curve(y_test, y_pred_proba)
    auc = sk.metrics.roc_auc_score(y_test, y_pred_proba)

    # Display confussion matrix
    cm = sk.metrics.confusion_matrix(y_test, y_pred)

    return {'acc': acc, 'prec': prec, 'rec': rec, 'f1': f1, 'kappa': kappa, 
            'fpr': fpr, 'tpr': tpr, 'auc': auc, 'cm': cm}

# Print result
def print_result(res):
    print('Accuracy:', res['acc'])
    print('Precision:', res['prec'])
    print('Recall:', res['rec'])
    print('F1 Score:', res['f1'])
    print('Cohens Kappa Score:', res['kappa'])
    print('Area Under Curve:', res['auc'])
    print('Confusion Matrix:\n', res['cm'])

def getModel(dataset):
    # If necessary to split training data
    # Select Features
    #feature = dataset.drop('isSafe', axis=1)
    X_train = dataset.drop('isSafe', axis=1)
    # Select Target
    #target = dataset["isSafe"]
    y_train = dataset["isSafe"]
    #model = tree.DecisionTreeClassifier(random_state=0)
    #model = RandomForestClassifier(random_state=0)
    #model = GaussianNB()
    model = KNeighborsClassifier()
    
    model.fit(X_train, y_train)
    
    return model
    
def getEvaluatedset(evalset, evalsetFile, model):
    output = pd.DataFrame()
    output["Identifier"] = evalset.loc[:,"name"]
    output["Label"] = model.predict(evalset.drop('name', axis=1))
    output["Label"] = output["Label"].apply(lambda x: 'malware' if x==0 else 'safe')
    
    output.to_csv(evalsetFile, index=False)

def evaluateModel (testset):
    X_train = testset.drop('isSafe', axis=1)
    # Select Target
    #target = dataset["isSafe"]
    y_train = testset["isSafe"]
    
    
    dtc = tree.DecisionTreeClassifier(random_state=0)
    dtc.fit(X_train, y_train)

    # Evaluate Model
    dtc_eval = evaluate_model(dtc, X_train, y_train)
    print_result(dtc_eval)
    
    # Building Random Forest model 
    rf = RandomForestClassifier(random_state=0)
    rf.fit(X_train, y_train)

    # Evaluate Model
    rf_eval = evaluate_model(rf, X_train, y_train)
    print_result(rf_eval)

    # Building Naive Bayes model 
    nb = GaussianNB()
    nb.fit(X_train, y_train)

    # Evaluate Model
    nb_eval = evaluate_model(nb, X_train, y_train)

    # Print result
    print_result(nb_eval)

    # Building KNN model 
    knn = KNeighborsClassifier()
    knn.fit(X_train, y_train)

    # Evaluate Model
    knn_eval = evaluate_model(knn, X_train, y_train)

    # Print result
    print_result(knn_eval)

    # Intitialize figure with two plots
    fig, (ax1, ax2) = plt.subplots(1, 2)
    fig.suptitle('Model Comparison', fontsize=16, fontweight='bold')
    fig.set_figheight(7)
    fig.set_figwidth(14)
    fig.set_facecolor('white')


    # First plot
    ## set bar size
    barWidth = 0.2
    dtc_score = [dtc_eval['acc'], dtc_eval['prec'], dtc_eval['rec'], dtc_eval['f1'], dtc_eval['kappa']]
    rf_score = [rf_eval['acc'], rf_eval['prec'], rf_eval['rec'], rf_eval['f1'], rf_eval['kappa']]
    nb_score = [nb_eval['acc'], nb_eval['prec'], nb_eval['rec'], nb_eval['f1'], nb_eval['kappa']]
    knn_score = [knn_eval['acc'], knn_eval['prec'], knn_eval['rec'], knn_eval['f1'], knn_eval['kappa']]

    ## Set position of bar on X axis
    r1 = np.arange(len(dtc_score))
    r2 = [x + barWidth for x in r1]
    r3 = [x + barWidth for x in r2]
    r4 = [x + barWidth for x in r3]

    ## Make the plot
    ax1.bar(r1, dtc_score, width=barWidth, edgecolor='white', label='Decision Tree')
    ax1.bar(r2, rf_score, width=barWidth, edgecolor='white', label='Random Forest')
    ax1.bar(r3, nb_score, width=barWidth, edgecolor='white', label='Naive Bayes')
    ax1.bar(r4, knn_score, width=barWidth, edgecolor='white', label='K-Nearest Neighbors')

    ## Configure x and y axis
    ax1.set_xlabel('Metrics', fontweight='bold')
    labels = ['Accuracy', 'Precision', 'Recall', 'F1', 'Kappa']
    ax1.set_xticks([r + (barWidth * 1.5) for r in range(len(dtc_score))], )
    ax1.set_xticklabels(labels)
    ax1.set_ylabel('Score', fontweight='bold')
    ax1.set_ylim(0, 1)

    ## Create legend & title
    ax1.set_title('Evaluation Metrics', fontsize=14, fontweight='bold')
    ax1.legend()

    # Second plot
    ## Comparing ROC Curve
    ax2.plot(dtc_eval['fpr'], dtc_eval['tpr'], label='Decision Tree, auc = {:0.5f}'.format(dtc_eval['auc']))
    ax2.plot(rf_eval['fpr'], rf_eval['tpr'], label='Random Forest, auc = {:0.5f}'.format(rf_eval['auc']))
    ax2.plot(nb_eval['fpr'], nb_eval['tpr'], label='Naive Bayes, auc = {:0.5f}'.format(nb_eval['auc']))
    ax2.plot(knn_eval['fpr'], knn_eval['tpr'], label='K-Nearest Nieghbor, auc = {:0.5f}'.format(knn_eval['auc']))

    ## Configure x and y axis
    ax2.set_xlabel('False Positive Rate', fontweight='bold')
    ax2.set_ylabel('True Positive Rate', fontweight='bold')

    ## Create legend & title
    ax2.set_title('ROC Curve', fontsize=14, fontweight='bold')
    ax2.legend(loc=4)

    plt.show()