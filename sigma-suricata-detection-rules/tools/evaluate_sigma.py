#!/usr/bin/env python3
"""Offline regression harness for the restricted Sigma subset in this lab.
Not a PySigma parser, production SIEM, or log ingestion pipeline.
"""
import argparse
import ast
import json
from pathlib import Path
import sys
import yaml

BASE = Path(__file__).resolve().parents[1]


def load_rules():
    rules=[]
    for p in sorted((BASE/'rules/sigma').rglob('*.yml')):
        with p.open(encoding='utf-8') as stream:
            doc=yaml.safe_load(stream)
        if not isinstance(doc,dict) or not {'title','id','logsource','detection'} <= doc.keys():
            raise ValueError(f'Invalid Sigma rule: {p}')
        rules.append((p,doc))
    return rules


def field_match(key, expected, event):
    parts=key.split('|')
    if len(parts)>2 or (len(parts)==2 and parts[1] not in ('contains','endswith','startswith')):
        raise ValueError(f'Unsupported field modifier: {key}')
    value=event.get(parts[0])
    if value is None: return False
    modifier=parts[1] if len(parts)==2 else 'exact'
    def one(x):
        a,b=str(value).casefold(),str(x).casefold()
        if modifier=='contains':return b in a
        if modifier=='endswith':return a.endswith(b)
        if modifier=='startswith':return a.startswith(b)
        return a==b
    return any(one(x) for x in expected) if isinstance(expected,list) else one(expected)


def selection_match(selection,event):
    if not isinstance(selection,dict): raise ValueError('Only mapping-based selections supported')
    return all(field_match(field,values,event) for field,values in selection.items())


def check_expr(node,values):
    if isinstance(node,ast.Name):
        if node.id not in values: raise ValueError('Unknown selection: '+node.id)
        return values[node.id]
    if isinstance(node,ast.BoolOp):
        operands=[check_expr(n,values) for n in node.values]
        if isinstance(node.op,ast.And): return all(operands)
        if isinstance(node.op,ast.Or): return any(operands)
    if isinstance(node,ast.UnaryOp) and isinstance(node.op,ast.Not): return not check_expr(node.operand,values)
    raise ValueError('Unsupported Sigma expression; this harness is intentionally limited')


def matches(rule,event,baseline=False):
    ls=rule['logsource']
    if any(event.get('logsource',{}).get(k)!=v for k,v in ls.items() if k!='definition'): return False
    detection=rule['detection']
    selections={k:selection_match(v,event) for k,v in detection.items() if k!='condition'}
    if baseline:
        # Baseline purposefully lacks the explicit *approved-parent* suppressions.
        # No arbitrary changes to the production rule are assumed.
        condition=detection['condition'].split(' and not ')[0]
    else:
        condition=detection['condition']
    return check_expr(ast.parse(condition,mode='eval').body,selections)


def metrics(rows):
    counts={'TP':0,'FP':0,'TN':0,'FN':0}
    for label,pred in rows:
        if label not in ('attack','benign'): raise ValueError('Unexpected label: '+label)
        cls=('T' if label=='attack' else 'F')+('P' if pred else 'N')
        # FN -> actual attack negative; TN -> actual benign negative
        if label=='attack' and not pred: cls='FN'
        if label=='benign' and not pred: cls='TN'
        counts[cls]+=1
    tp,fp,tn,fn=(counts[k] for k in ('TP','FP','TN','FN'))
    counts.update(recall=round(100*tp/(tp+fn),2) if (tp+fn)>0 else None,
                  precision=round(100*tp/(tp+fp),2) if (tp+fp)>0 else None,
                  fpr=round(100*fp/(fp+tn),2) if (fp+tn)>0 else None)
    return counts


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--events',type=Path,default=BASE/'sample-data/sigma_events.jsonl')
    parser.add_argument('--output',type=Path,default=None,help='Optional metrics JSON output')
    a=parser.parse_args()
    rules=load_rules()
    rows=[]; baseline_rows=[]; misses=[]; false_positives=[]
    for line in a.events.read_text(encoding='utf-8').splitlines():
        if not line.strip():continue
        event=json.loads(line)
        matched=[p.stem for p,rule in rules if matches(rule,event)]
        baseline_matched=[p.stem for p,rule in rules if matches(rule,event,baseline=True)]
        rows.append((event['label'],bool(matched)))
        baseline_rows.append((event['label'],bool(baseline_matched)))
        if event['label']=='attack' and not matched: misses.append(event['case_id'])
        if event['label']=='benign' and matched: false_positives.append((event['case_id'],matched))
    tuned=metrics(rows); baseline=metrics(baseline_rows)
    reduction=round(100*(baseline['FP']-tuned['FP'])/baseline['FP'],2) if baseline['FP'] else None
    report={'source':'synthetic Sigma event fixtures; restricted-subset evaluator, not SIEM validation',
            'rules':len(rules),'events':len(rows),'baseline':baseline,'tuned':tuned,
            'false_positive_reduction_pct':reduction,'missed_attack_case_ids':misses,
            'false_positives':false_positives}
    print(json.dumps(report,indent=2))
    if a.output:
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')

if __name__=='__main__': main()
