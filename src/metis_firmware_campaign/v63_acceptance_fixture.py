# SPDX-License-Identifier: Apache-2.0
"""Deterministic fail-point adapter used only by reusable v6.3 acceptance."""
import argparse,hashlib,json,os,pathlib,shutil,sqlite3
P=pathlib.Path
def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def h(x):return hashlib.sha256(canon(x)).hexdigest()
def save(p,x):p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(canon(x)+b'\n')
def packet(records,integrator=False,version='6.3'):
 x={'contract_version':version,'review_provenance':{'subject_binding':'SCANNER_RECORD'},'authoritative_integrator':integrator,'campaign_write_attempts':0,'records':records};x['packet_sha256']=h(x);return x
def deferred(i):return {'record_id':f'fixture:{i:02d}','decision_status':'NON_TERMINAL','technical_class':'DEFERRED','programme_scope':'UNRESOLVED','scanner_claim_status':'UNRESOLVED','source_reread':True,'decisive_sources':[],'reopen_condition':'synthetic acceptance fixture','creates_root':False}
def bump(path,key):
 p=P(path);d=json.loads(p.read_text()) if p.exists() else {};d[key]=d.get(key,0)+1;save(p,d)
def main():
 p=argparse.ArgumentParser();p.add_argument('--stage',required=True);p.add_argument('--context',required=True);a=p.parse_args();c=json.loads(P(a.context).read_text());o=P(c['output_directory']);o.mkdir(parents=True,exist_ok=True);ledger=os.environ['V63_CALL_LEDGER'];bump(ledger,'adapter:'+a.stage)
 if a.stage=='metis-one':
  cp=P(c['provider_checkpoint_root'])/'result-000.json'
  if not cp.exists():save(cp,{'result':'committed'});bump(ledger,'provider_calls')
 if os.environ.get('V63_INTERRUPT_STAGE')==a.stage and not P(ledger+'.'+a.stage+'.failed').exists():save(P(ledger+'.'+a.stage+'.failed'),{'failed':True});raise SystemExit(73)
 outputs={'collect-source':['source-manifest.json','active-source-membership.json','indirect-call-inventory.json','documentation-manifest.json','component-registry.json'],'collect-historical-tickets':['historical-ticket-manifest.json','ticket-source-relations.json','connector-receipts.json'],'collect-current-tickets':['current-ticket-manifest.json','ticket-source-relations.json','connector-receipts.json'],'collect-threat-policy':['threat-policy-manifest.json','connector-receipts.json','security-properties.json','programme-rules.json','advisory-fix-regression.json','programme-threat-comparison.json'],'build-candidate':['candidate-build.json','contract-discovery.json','exact-build-bindings.json','knowledge-fts.json','independent-rebuild.json'],'metis-health':['provider-health.json'],'metis-one':['calibration.json'],'metis-twenty':['calibration.json'],'metis-full':['incremental-finalization.json','rendered-prompt-receipts.json','coverage-schedules.json','context-cache-receipts.json'],'metis-capacity':['capacity-decision.json'],'validate-packets':['stage.json','terminal-decision-capsules.json','review-bindings.json','fp-no-bug-audits.json','classification-reopen-proposals.json','terminal-change-anomaly-gate.json'],'integrate':['integration.packet.json','root-fingerprints.json','fts-index-receipt.json','root-property-mappings.json','variant-searches.json','scope-invalidation.json'],'reproduce':['reproduction-frontier.json','backend-capabilities.json','rerun-manifests.json','reproducer-reuse.json','candidate-patch-state.json','control-triplets.json'],'package-seal':['candidate-a.db','candidate-b.db','candidate-a.dump','candidate-b.dump','report-a.md','report-b.md','delivery-a.json','delivery-b.json','packages-a/manifest.json','packages-b/manifest.json','validation-gates.json','current-frontier.json','final-receipts.json']}
 if a.stage=='build-candidate':
  P(c['candidate_path']).parent.mkdir(parents=True,exist_ok=True);db=sqlite3.connect(c['candidate_path']);db.executescript("CREATE TABLE IF NOT EXISTS project(project_id TEXT PRIMARY KEY);CREATE TABLE IF NOT EXISTS root(root_id TEXT PRIMARY KEY,current_decision TEXT,source_hash TEXT);CREATE TABLE IF NOT EXISTS validation_run(validation_run_id TEXT PRIMARY KEY,reproduction_level TEXT,reproduction_workflow_status TEXT,severity_reference TEXT,manifest_hash TEXT,structured_receipt_hash TEXT);CREATE TABLE IF NOT EXISTS validation_run_root(validation_run_id TEXT,root_id TEXT);CREATE TABLE IF NOT EXISTS poc_artifact(validation_run_id TEXT,artifact_role TEXT,content_hash TEXT);CREATE TABLE IF NOT EXISTS execution_observation(validation_run_id TEXT,observation_role TEXT,status TEXT,artifact_hash TEXT,evidence_hash TEXT);CREATE TABLE IF NOT EXISTS snapshot(snapshot_id TEXT PRIMARY KEY,kind TEXT);CREATE TABLE IF NOT EXISTS campaign_import(import_id TEXT PRIMARY KEY,snapshot_id TEXT,source_count INTEGER,retained_count INTEGER,rejected_count INTEGER);CREATE TABLE IF NOT EXISTS campaign_subject(record_id TEXT PRIMARY KEY,import_id TEXT,technical_class TEXT);CREATE TABLE IF NOT EXISTS campaign_record_root(record_id TEXT,root_id TEXT);");db.execute("INSERT OR IGNORE INTO project VALUES('fixture')");db.commit();db.close()
 if a.stage=='validate-worker':save(o/f"worker-{int(c['worker_id']):02d}.packet.json",packet([deferred(int(c['worker_id']))],version=c['profile_schema_version']));return
 if a.stage=='integrate':
  records=[]
  for z in c['dependency_outputs']['validate-packets']:
   if z['locator'].endswith('.packet.json'):records.extend(json.loads(P(z['locator']).read_text())['records'])
  save(o/'integration.packet.json',packet(records,True,c['profile_schema_version']))
 if a.stage=='package-seal':
  src=P(c['candidate_path']);shutil.copyfile(src,o/'candidate-a.db');shutil.copyfile(src,o/'candidate-b.db');dump='fixture logical dump\n'
  for n in ('candidate-a.dump','candidate-b.dump'):P(o/n).write_text(dump)
  for n in ('report-a.md','report-b.md'):P(o/n).write_text('fixture report\n')
  for n in ('delivery-a.json','delivery-b.json','packages-a/manifest.json','packages-b/manifest.json'):save(o/n,{'fixture':True})
 if a.stage=='collect-threat-policy' and c['profile_schema_version'] in {'6.6','6.6.1','6.7'}:
  empty={'technical':[],'reproduction':[],'severity':[],'observations':[]};save(o/'policy-reconciliation-input.json',{'format_version':'firmware-policy-reconciliation-input-v6.6','project_id':'fixture','policy_snapshot_hash':'1'*64,'ticket_snapshot_hash':'2'*64,'technical_projection_hash':h(empty),'roots':[]})
 for n in outputs[a.stage]:
  if (o/n).exists():continue
  save(o/n,{'stage':a.stage,'output':n,'complete':True})
if __name__=='__main__':main()
