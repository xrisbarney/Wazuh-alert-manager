#!/usr/bin/env python3
"""Reliability-run kit for Wazuh Alert Manager (SoftwareX Impact evaluation).

Generates a TAGGED synthetic Wazuh-alert corpus with known ground-truth
outcomes and measures what the automation engine actually did, so precision can
be reported (expected vs. actual, plus false actions on benign filler alerts).

Run ON the Wazuh node. Credentials come from the environment:
    export WAM_USER=admin
    export WAM_PW=<indexer password>
    export WAM_INDEXER=https://localhost:9200     # optional, this is the default

Usage:
    python3 bench.py gen     <RUNID>                    # emit bulk NDJSON to stdout
    python3 bench.py measure <RUNID> <caseRuleIdsCSV>   # print actual outcomes as JSON

See README.md for the orchestration wrapper and the expected results table.
"""
import sys, os, json, ssl, base64, time, urllib.request

USER = os.environ.get('WAM_USER', 'admin')
PW = os.environ.get('WAM_PW', '')
BASE = os.environ.get('WAM_INDEXER', 'https://localhost:9200')
STATUS = 'wazuh-alert-status'
CASES = 'wazuh-alert-manager-cases'

def now_iso(offset=25):  # slightly future, so alerts sit ahead of the sync watermark
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(time.time() + offset)) + '.000Z'

def doc(runid, group, agent, ruleid, level, srcip=None, srcuser=None):
    d = {'@timestamp': now_iso(), 'agent': {'name': agent, 'id': '000'},
         'rule': {'id': str(ruleid), 'level': level, 'description': 'paperbench ' + group},
         'manager': {'name': 'paperbench'},
         'data': {'paperbench': runid, 'pbgroup': group}}
    if srcip:
        d['data']['srcip'] = srcip
    if srcuser:
        d['data']['srcuser'] = srcuser
    return d

def gen(runid):
    out = []
    def add(d):
        out.append(json.dumps({'index': {}})); out.append(json.dumps(d))
    # A - srcip burst >=5 : 5 firing IPs x6 (=>5 cases, 30 linked), 3 non-firing x3
    for i in range(5):
        for _ in range(6): add(doc(runid, 'A', 'pbench-a', 900002, 5, srcip='10.0.1.%d' % i))
    for i in range(5, 8):
        for _ in range(3): add(doc(runid, 'A', 'pbench-a', 900002, 5, srcip='10.0.1.%d' % i))
    # B - per-alert auto-close (rule 900001) x20 : => 20 closed
    for _ in range(20): add(doc(runid, 'B', 'pbench-b', 900001, 5))
    # C - user burst >=4 : 3 firing users x5 (=>15 in_progress+assigned), 1 non-firing x2
    for i in range(3):
        for _ in range(5): add(doc(runid, 'C', 'pbench-c', 900003, 5, srcuser='user%d' % i))
    for _ in range(2): add(doc(runid, 'C', 'pbench-c', 900003, 5, srcuser='user9'))
    # D - all-of [900010,900011] per agent, threshold 2 : 2 agents both ids (=>2 cases,4 linked),
    #     1 agent only 900010 x2 (coverage fails => 0)
    for a in ['pbench-d-1', 'pbench-d-2']:
        add(doc(runid, 'D', a, 900010, 5)); add(doc(runid, 'D', a, 900011, 5))
    add(doc(runid, 'D', 'pbench-d-3', 900010, 5)); add(doc(runid, 'D', 'pbench-d-3', 900010, 5))
    # F - 1000 benign fillers (level 2) : => 0 actions (precision check)
    for _ in range(1000): add(doc(runid, 'F', 'pbench-f', 900099, 2))
    sys.stdout.write('\n'.join(out) + '\n')

def _req(path, body=None, method='GET'):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    r.add_header('Authorization', 'Basic ' + base64.b64encode(('%s:%s' % (USER, PW)).encode()).decode())
    r.add_header('Content-Type', 'application/json')
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    return json.loads(urllib.request.urlopen(r, context=ctx, timeout=30).read())

def _count(index, query):
    return _req('/%s/_count' % index, {'query': query}, 'POST').get('count', 0)

def kwt(field, val):  # tolerate data.* mapped as keyword (fresh) or text+keyword (older index)
    return {'bool': {'should': [{'term': {field: val}}, {'term': {field + '.keyword': val}}], 'minimum_should_match': 1}}

def measure(runid, case_rule_ids):
    def q(extra):
        return {'bool': {'must': [kwt('data.paperbench', runid)] + extra}}
    by = {g: _count(STATUS, q([kwt('data.pbgroup', g)])) for g in ['A', 'B', 'C', 'D', 'F']}
    acted_filler = _count(STATUS, q([kwt('data.pbgroup', 'F'), {'bool': {'should': [
        {'term': {'status': 'closed'}}, {'term': {'status': 'in_progress'}},
        {'exists': {'field': 'case_id'}}, {'exists': {'field': 'assigned_to'}}], 'minimum_should_match': 1}}]))
    rule_cases = 0
    for rid in case_rule_ids:
        rule_cases += _count(CASES, {'bool': {'must': [{'term': {'created_by': 'correlation-rule'}},
                                                       {'prefix': {'correlation_key': rid + '|'}}]}})
    print(json.dumps({
        'runid': runid, 'total_synced': sum(by.values()), 'by_group': by,
        'closed_B': _count(STATUS, q([kwt('data.pbgroup', 'B'), {'term': {'status': 'closed'}}])),
        'inprog_C': _count(STATUS, q([kwt('data.pbgroup', 'C'), {'term': {'status': 'in_progress'}}])),
        'assigned_C': _count(STATUS, q([kwt('data.pbgroup', 'C'), {'term': {'assigned_to': 'admin'}}])),
        'linked_A': _count(STATUS, q([kwt('data.pbgroup', 'A'), {'exists': {'field': 'case_id'}}])),
        'linked_D': _count(STATUS, q([kwt('data.pbgroup', 'D'), {'exists': {'field': 'case_id'}}])),
        'rule_cases_created': rule_cases, 'false_actions_on_fillers': acted_filler,
    }, indent=2))

if __name__ == '__main__':
    if len(sys.argv) < 3 or not PW:
        sys.stderr.write('set WAM_PW (and optionally WAM_USER/WAM_INDEXER); usage: bench.py gen|measure ...\n'); sys.exit(2)
    if sys.argv[1] == 'gen':
        gen(sys.argv[2])
    elif sys.argv[1] == 'measure':
        measure(sys.argv[2], sys.argv[3].split(','))
