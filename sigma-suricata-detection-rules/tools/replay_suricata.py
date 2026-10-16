#!/usr/bin/env python3
"""Replays individually labeled lab PCAPs in installed Suricata and scores EVE alerts.
Requires actual Suricata binary and network config; no mock alerts.
"""
import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from evaluate_sigma import metrics
BASE=Path(__file__).resolve().parents[1]

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--config',default='/etc/suricata/suricata.yaml')
    p.add_argument('--suricata',default='suricata')
    p.add_argument('--pcaps',type=Path,default=BASE/'outputs/pcaps')
    a=p.parse_args()
    config=Path(a.config); rules=BASE/'suricata/custom.rules'
    cases=json.loads((BASE/'tests/fixtures/suricata_cases.json').read_text())
    # Suricata uses HOME_NET from YAML. Fixtures expect 192.168.1.0/24 HOME_NET.
    prefix=[a.suricata,'-c',str(config),'-S',str(rules)]
    print('Checking Suricata rules with actual engine (not Python simulation)...')
    with tempfile.TemporaryDirectory(prefix='suricata-validate-') as check_dir:
        v=subprocess.run(prefix+['-l',check_dir,'-T'],capture_output=True,text=True)
    if v.returncode:
        raise SystemExit(f'Suricata configuration test failed:\n{v.stdout[-3000:]}\n{v.stderr[-3000:]}')
    rows=[]; results=[]
    with tempfile.TemporaryDirectory(prefix='suricata-lab-') as tmp:
        for case in cases:
            case_id=case['case_id']; pcap=a.pcaps/(case_id+'.pcap')
            if not pcap.is_file(): raise SystemExit('Missing '+str(pcap)+'; run generate_pcaps.py first')
            out=Path(tmp)/case_id; out.mkdir()
            proc=subprocess.run(prefix+['-r',str(pcap),'-l',str(out)],capture_output=True,text=True)
            if proc.returncode: raise SystemExit(f'Error in {case_id}: {proc.stderr[-3000:]}\n{proc.stdout[-2000:]}')
            eve=out/'eve.json'
            if not eve.is_file():raise SystemExit(f'Missing {eve}; configure EVE alert output in Suricata YAML')
            sids=[]
            for line in eve.read_text().splitlines():
                obj=json.loads(line)
                if obj.get('event_type')=='alert':
                    sid=obj.get('alert',{}).get('signature_id')
                    if sid and 4200001<=int(sid)<=4200008: sids.append(int(sid))
            sids=sorted(set(sids)); detected=bool(sids)
            rows.append((case['label'],detected))
            results.append({'case_id':case_id,'label':case['label'],'detected':detected,'matched_sids':sids})
    result={'source':'actual Suricata offline replay with synthetically crafted PCAPs',
            'cases':results,'metrics':metrics(rows)}
    print(json.dumps(result,indent=2))
    target=BASE/'outputs/suricata_metrics.json'; target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__':main()
