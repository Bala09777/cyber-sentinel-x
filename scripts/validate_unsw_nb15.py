"""Validate UNSW-NB15 experimental shadow model on the supplied held-out split.

This is NOT the production 6-feature network anomaly model. Inputs are
spkts, sbytes, dur, proto and may differ from real observed packet flows.
Usage: python scripts/validate_unsw_nb15.py --train <csv> --test <csv>
"""
import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
PROTOCOLS = {'tcp':0,'udp':1,'icmp':2}


def load(path):
    features, labels = [], []
    by_proto = {x:0 for x in PROTOCOLS}
    total = 0
    with open(path, newline='', encoding='utf-8-sig') as stream:
        for row in csv.DictReader(stream):
            total += 1
            proto = row['proto'].lower()
            if proto not in PROTOCOLS:
                continue
            try:
                vector = [float(row['spkts']),float(row['sbytes']),
                          float(row['dur']),float(PROTOCOLS[proto])]
                label = int(row['label'])
                if label not in (0,1) or not np.isfinite(vector).all():
                    continue
            except (ValueError,TypeError,KeyError):
                continue
            features.append(vector)
            labels.append(label)
            by_proto[proto]+=1
    return np.array(features,dtype=np.float32),np.array(labels,dtype=np.int8),{'total':total,'included':len(labels),'by_protocol':by_proto}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--train',required=True)
    parser.add_argument('--test',required=True)
    parser.add_argument('--out',default=str(ROOT/'models'/'unsw_nb15_validated.joblib'))
    parser.add_argument('--report',default=str(ROOT/'models'/'unsw_nb15_validation.json'))
    args=parser.parse_args()
    xtrain,ytrain,trainmeta=load(args.train)
    xtest,ytest,testmeta=load(args.test)
    if not len(xtrain) or not len(xtest) or len(set(ytrain))<2 or len(set(ytest))<2:
        raise SystemExit('Insufficient normal/attack examples for training and validation')
    print('Train:', trainmeta, 'Test:', testmeta, flush=True)
    model=RandomForestClassifier(n_estimators=60,max_depth=12,min_samples_leaf=5,
                                 class_weight='balanced',random_state=42,n_jobs=4)
    model.fit(xtrain,ytrain)
    ypred=model.predict(xtest)
    scores=model.predict_proba(xtest)[:,list(model.classes_).index(1)]
    metrics=classification_report(ytest,ypred,target_names=['normal','attack'],
                                  output_dict=True,zero_division=0)
    report={'dataset':'UNSW-NB15 official supplied train/test splits',
        'feature_names':['spkts','sbytes','dur','proto_code'],
        'included_protocols':list(PROTOCOLS),
        'training':trainmeta,'testing':testmeta,
        'confusion_matrix_rows_true_0_1':confusion_matrix(ytest,ypred).tolist(),
        'classification_report':metrics, 'roc_auc':float(roc_auc_score(ytest,scores)),
        'tested_at_utc':datetime.now(timezone.utc).isoformat(),
        'scope':'EXPERIMENTAL SHADOW CLASSIFIER; not production model; no real-world validation; no alerts triggered by this model.'}
    Path(args.out).parent.mkdir(parents=True,exist_ok=True)
    joblib.dump(model,args.out)
    Path(args.report).write_text(json.dumps(report,indent=2))
    print('Accuracy:',metrics['accuracy'],'Attack F1:',metrics['attack']['f1-score'],'ROC AUC:',report['roc_auc'], flush=True)
    print('Saved:',args.out,'Report:',args.report,flush=True)

if __name__=='__main__':main()
