import json
import re
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from evaluate_sigma import load_rules,matches,metrics

class DetectionTests(unittest.TestCase):
    def test_rule_counts_ids_and_structure(self):
        rules=load_rules()
        self.assertEqual(len(rules),15)
        ids=[r['id'] for _,r in rules]
        self.assertEqual(len(ids),len(set(ids)))
        for _,r in rules:
            self.assertIn(r['logsource']['product'],('windows','linux'))
            self.assertIn('condition',r['detection'])
    def test_suricata_rules_and_sids(self):
        signatures=[line for line in (ROOT/'suricata/custom.rules').read_text().splitlines() if line.startswith('alert ')]
        self.assertEqual(len(signatures),8)
        sids=[re.search(r'; sid:(\d+);',s).group(1) for s in signatures]
        self.assertEqual(len(sids),len(set(sids)))
    def test_synthetic_fixture_predictions(self):
        rules=load_rules()
        cases=[json.loads(l) for l in (ROOT/'tests/fixtures/sigma_events.jsonl').read_text().splitlines()]
        for case in cases:
            with self.subTest(case_id=case['case_id']):
                fired=any(matches(r,case) for _,r in rules)
                self.assertEqual(fired,case['label']=='attack')
    def test_metrics(self):
        self.assertEqual(metrics([('attack',True),('attack',False),('benign',True),('benign',False)])['recall'],50.0)
        self.assertEqual(metrics([('attack',True),('attack',False),('benign',True),('benign',False)])['fpr'],50.0)

if __name__=='__main__': unittest.main()
