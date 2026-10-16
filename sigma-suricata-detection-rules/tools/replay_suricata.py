#!/usr/bin/env python3
"""Replays individually labeled lab PCAPs in installed Suricata and scores EVE alerts.
Requires actual Suricata binary and network config; no mock alerts.
"""
import argparse
import json
import hashlib
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
    p.add_argument('--output-dir', type=Path, help='New directory for retained engine evidence')
    a=p.parse_args()
    config=Path(a.config); rules=BASE/'rules/suricata/custom.rules'
    cases=json.loads((BASE/'sample-data/suricata_cases.json').read_text())
    # Suricata uses HOME_NET from YAML. Fixtures expect 192.168.1.0/24 HOME_NET.
    prefix=[a.suricata,'-c',str(config),'-S',str(rules)]
    # Keep actual engine output, including failed runs, for review.
    outputs = BASE / 'outputs'
    outputs.mkdir(exist_ok=True)
    if a.output_dir:
        work = a.output_dir.resolve()
        work.mkdir(parents=True, exist_ok=False)
    else:
        work = Path(tempfile.mkdtemp(prefix='suricata-replay-', dir=outputs))
    print('Evidence directory:', work)
    version = subprocess.run([a.suricata, '--build-info'], capture_output=True, text=True)
    (work / 'engine-version.txt').write_text(version.stdout + version.stderr)
    check_dir = work / 'engine-check'
    check_dir.mkdir()
    v = subprocess.run(prefix + ['-l', str(check_dir), '-T'], capture_output=True, text=True)
    (check_dir / 'command.log').write_text(v.stdout + v.stderr)
    if v.returncode:
        raise SystemExit(f'Suricata configuration test failed; inspect {check_dir}')
    rows=[]; results=[]
    for case in cases:
        case_id=case['case_id']; pcap=a.pcaps/(case_id+'.pcap')
        if not pcap.is_file(): raise SystemExit('Missing '+str(pcap)+'; run generate_pcaps.py first')
        out=work/case_id; out.mkdir()
        proc=subprocess.run(prefix+['-r',str(pcap),'-l',str(out),'-k','none','--runmode','single'],capture_output=True,text=True)
        (out / 'command.log').write_text(proc.stdout + proc.stderr)
        if proc.returncode: raise SystemExit(f'Engine error in {case_id}; inspect {out}')
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
        results.append({'case_id':case_id,'label':case['label'],'detected':detected,'matched_sids':sids,
                        'pcap_sha256':hashlib.sha256(pcap.read_bytes()).hexdigest()})
    result={'source':'actual Suricata offline replay with synthetically crafted PCAPs',
            'cases':results,'metrics':metrics(rows), 'evidence_directory':str(work),
            'rules_sha256':hashlib.sha256(rules.read_bytes()).hexdigest(),
            'config_sha256':hashlib.sha256(config.read_bytes()).hexdigest()}
    (work / 'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    target=BASE/'outputs/suricata_metrics.json'; target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__':main()
