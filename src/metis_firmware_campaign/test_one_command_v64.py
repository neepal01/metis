# SPDX-License-Identifier: Apache-2.0
"""Clean one-command/resume acceptance for the generic v6.4 package stage."""
import json,pathlib,subprocess,sys,tempfile,os
from .test_one_command_v63 import make
P=pathlib.Path;HERE=P(__file__).resolve().parent;REPO=HERE.parents[1]

def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()

def main():
 with tempfile.TemporaryDirectory() as td:
  root=P(td);source=make(root);path=root/'profile.json';profile=json.loads(path.read_text())
  profile['schema_version']='6.4';profile['contract_release']['version']='6.4.0'
  seal=next(x for x in profile['automation']['stages'] if x['phase']=='PACKAGE_AND_SEAL')
  seal['depends_on'].append('package-export')
  profile['automation']['stages'].insert(-1,{'stage_id':'package-export','phase':'PACKAGE_EXPORT','depends_on':['integrate','reproduce'],'builtin':'INTERNAL_TECHNICAL_PACKAGE_EXPORT','required_outputs':['INDEX.json','INDEX.md','VALIDATION-RECEIPT.json']})
  path.write_bytes(canon(profile)+b'\n');ledger=root/'calls.json';env={**os.environ,'V63_CALL_LEDGER':str(ledger),'V63_INTERRUPT_STAGE':'reproduce'}
  cmd=['uv','run','--no-sync','metis','--firmware-campaign',str(path),'--codebase-path',str(source),'--resume']
  first=subprocess.run(cmd,cwd=REPO,env=env,capture_output=True,text=True);env.pop('V63_INTERRUPT_STAGE')
  second=subprocess.run(cmd,cwd=REPO,env=env,capture_output=True,text=True)
  calls_before=ledger.read_bytes();third=subprocess.run(cmd,cwd=REPO,env=env,capture_output=True,text=True);calls=json.loads(ledger.read_text())
  indexes=list((root/'automation/stages/package-export').glob('*/INDEX.json'))
  index=json.loads(indexes[0].read_text()) if len(indexes)==1 else {}
  ok=first.returncode!=0 and second.returncode==0 and third.returncode==0 and calls_before==ledger.read_bytes() and len(indexes)==1 and index.get('counts')=={'IN_SCOPE':0,'UNRESOLVED':0,'OOS':0} and index.get('supplemental_packaging_prompt_required') is False and calls.get('provider_calls')==1 and 'adapter:package-export' not in calls
  result={'format_version':'firmware-capability-v6.4-one-command-acceptance','result':'PASS' if ok else 'FAIL','first_interrupted':first.returncode!=0,'resume_passed':second.returncode==0,'stable_resume':third.returncode==0 and calls_before==ledger.read_bytes(),'provider_completed_calls_repeated':0 if calls.get('provider_calls')==1 else None,'generic_package_stage_used':len(indexes)==1 and 'adapter:package-export' not in calls,'supplemental_packaging_prompt_required':index.get('supplemental_packaging_prompt_required'),'errors':[] if ok else [first.stderr[-500:],second.stderr[-1000:],third.stderr[-500:]]}
  print(json.dumps(result,sort_keys=True));return not ok
if __name__=='__main__':raise SystemExit(main())
