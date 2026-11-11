import json
import os
from pathlib import Path
import shutil
import sqlite3
import argparse

import pytest

from metis_firmware_campaign import technical_adjudication as adjudication
from metis_firmware_campaign import technical_state_correction as state_control
from metis_firmware_campaign import autonomous_campaign as campaign


def write_record(path: Path, value: dict) -> None:
    value["content_hash"] = adjudication.object_hash(value)
    path.write_text(json.dumps(value, sort_keys=True))


def bind(path: Path) -> dict:
    return {
        "locator": str(path.resolve()),
        "sha256": adjudication.file_hash(path),
        "size": path.stat().st_size,
    }


def dependency_manifest_hash(candidate: Path, build_id: str = "build:test") -> str:
    with sqlite3.connect(candidate) as database:
        columns = [row[1] for row in database.execute("PRAGMA table_info(exact_build_binding)")]
        rows = [
            dict(zip(columns, row))
            for row in database.execute(
                "SELECT * FROM exact_build_binding WHERE build_id=? ORDER BY dependency_kind,locator,binding_id",
                (build_id,),
            )
        ]
    return adjudication.object_hash(
        {
            "build_id": build_id,
            "dependencies": [
                {
                    key: row[key]
                    for key in ("binding_id", "dependency_kind", "locator", "content_hash", "status", "reason")
                }
                for row in rows
            ],
        }
    )


def create_database(path: Path, decision: str | None = None, relation: str = "NONE") -> None:
    with sqlite3.connect(path) as database:
        database.executescript(
            """
            CREATE TABLE campaign_subject(record_id TEXT PRIMARY KEY,import_id TEXT,project_id TEXT,ticket_id TEXT,title TEXT,raw_hash TEXT,technical_class TEXT,programme_scope TEXT,scanner_claim_status TEXT,processing_route TEXT,reproduction_level TEXT,decision_status TEXT,campaign_phase TEXT);
            CREATE TABLE terminal_decision_capsule(capsule_id TEXT PRIMARY KEY,project_id TEXT,record_id TEXT UNIQUE,root_id TEXT,terminal_decision TEXT,proof_tuple_json TEXT,counterevidence TEXT,decisive_sources_json TEXT,build_id TEXT,configuration_hash TEXT,dependency_manifest_hash TEXT,review_set_hash TEXT,reopen_conditions_json TEXT,content_hash TEXT);
            CREATE TABLE review_run(review_id TEXT PRIMARY KEY,role TEXT,model_tool TEXT,prompt_policy_hash TEXT,rendered_prompt_hash TEXT,reviewed_at TEXT,independent INTEGER,independence_basis TEXT,conclusion TEXT,content_hash TEXT);
            CREATE TABLE review_binding(binding_id TEXT PRIMARY KEY,review_id TEXT,subject_kind TEXT,subject_id TEXT,subject_hash TEXT,evidence_hash TEXT);
            CREATE TABLE fp_no_bug_audit(audit_id TEXT PRIMARY KEY,record_id TEXT,primary_review_id TEXT,blind_review_id TEXT,primary_decision TEXT,blind_decision TEXT,integrator_decision TEXT,counterevidence_category TEXT,decisive_source_manifest_hash TEXT,source_revision TEXT,build_id TEXT,configuration_hash TEXT,disagreement TEXT,arbitration_status TEXT,arbitration_evidence_hash TEXT,prior_terminal_capsule_hash TEXT,content_hash TEXT);
            CREATE TABLE build_capsule(build_id TEXT PRIMARY KEY,project_id TEXT,source_revision TEXT,platform TEXT,configuration_hash TEXT,toolchain TEXT,toolchain_hash TEXT,execution_target TEXT,identity_json TEXT,content_hash TEXT,status TEXT);
            CREATE TABLE exact_build_binding(binding_id TEXT PRIMARY KEY,build_id TEXT,dependency_kind TEXT,locator TEXT,content_hash TEXT,status TEXT,reason TEXT);
            CREATE TABLE root(root_id TEXT PRIMARY KEY,project_id TEXT,title TEXT,attacker_source TEXT,entry_flow TEXT,missing_control TEXT,security_sink TEXT,concrete_effect TEXT,boundary_configuration TEXT,current_decision TEXT,source_hash TEXT,source_hash_kind TEXT);
            CREATE TABLE root_fingerprint_field(root_id TEXT PRIMARY KEY,attacker_input TEXT,entry_function TEXT,sink_function TEXT,missing_check TEXT,violated_invariant TEXT,affected_state TEXT,primitive TEXT,precondition TEXT,fix_function TEXT,fix_signature TEXT,revision TEXT,configuration_hash TEXT,fingerprint_hash TEXT UNIQUE);
            CREATE TABLE fingerprint(fingerprint_id TEXT PRIMARY KEY,root_id TEXT,invariant TEXT,fields_json TEXT,fingerprint_hash TEXT UNIQUE);
            CREATE TABLE code_location(location_id TEXT PRIMARY KEY,root_id TEXT,component_id TEXT,path TEXT,line_start INTEGER,line_end INTEGER,revision TEXT,file_hash TEXT);
            CREATE TABLE call_path(call_path_id TEXT PRIMARY KEY,root_id TEXT,entry TEXT,sink TEXT,authority_state TEXT,content_hash TEXT);
            CREATE TABLE call_edge(edge_id TEXT PRIMARY KEY,call_path_id TEXT,seq INTEGER,caller TEXT,callee TEXT,authority_state TEXT,source_location TEXT);
            CREATE TABLE root_property_relation(relation_id TEXT PRIMARY KEY,root_id TEXT,property_id TEXT,threat_id TEXT,boundary_id TEXT,relation_status TEXT,applicability TEXT,evidence_id TEXT,evidence_hash TEXT,programme_scope_independent INTEGER);
            CREATE TABLE root_threat_assessment(assessment_id TEXT PRIMARY KEY,root_id TEXT UNIQUE,threat_id TEXT,boundary_id TEXT,attacker_role TEXT,entry_function TEXT,status TEXT,evidence TEXT,evidence_hash TEXT);
            CREATE TABLE campaign_record_root(record_id TEXT,root_id TEXT,relationship TEXT,confidence TEXT,PRIMARY KEY(record_id,root_id));
            CREATE TABLE policy_rule_decision_binding(binding_id TEXT PRIMARY KEY,root_id TEXT,dimension_outcome TEXT,content_hash TEXT);
            CREATE VIRTUAL TABLE knowledge_fts USING fts5(subject_kind UNINDEXED,subject_id UNINDEXED,title,body);
            """
        )
        database.execute(
            "INSERT INTO build_capsule VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("build:test", "project:test", "a"*40, "test", "c"*64, "test", "d"*64, "offline", "{}", "b"*64, "BUILT"),
        )
        database.execute(
            "INSERT INTO exact_build_binding VALUES(?,?,?,?,?,?,?)",
            ("build-binding:test", "build:test", "GENERATED_CONFIGURATION", "config", "d"*64, "VERIFIED", "hash-bound"),
        )
        database.executemany(
            "INSERT INTO campaign_subject VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (f"record:{index}", "import:current", "project:test", None, f"title {index}", f"raw:{index}", "DEFERRED", "UNKNOWN", "INCONCLUSIVE", "TRIAGE", "NOT_REPRODUCED", "NON_TERMINAL", "VALIDATION")
                for index in range(30)
            ] + [(f"historical:{index}", "import:historical", "project:test", None, f"historical {index}", f"historical-raw:{index}", "DEFERRED", "UNKNOWN", "INCONCLUSIVE", "TRIAGE", "NOT_REPRODUCED", "NON_TERMINAL", "VALIDATION") for index in range(21)],
        )
        if relation == "EXACT_DUPLICATE":
            database.execute("INSERT INTO root VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",("root:existing","project:test","existing","attacker","entry","check","sink","effect","config","VALID_VULNERABILITY","s"*64,"SHA256_DECISIVE_SOURCE_MANIFEST"))
            database.execute("INSERT INTO root_fingerprint_field VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",("root:existing","packet","entry","sink","check","invariant","state","primitive","none","fix","sig","a"*40,"c"*64,"f"*64))
            database.execute("INSERT INTO fingerprint VALUES('fingerprint:existing','root:existing','invariant','{}',?)",("f"*64,))
        if decision:
            database.execute(
                "UPDATE campaign_subject SET technical_class=?,decision_status='TERMINAL' WHERE record_id='record:0'",
                (decision,),
            )


def add_successor_material(root: Path, successor: Path, decision: str, relation: str, malformed: bool = False) -> dict:
    evidence = root / "technical-evidence.json"
    proof = {"attacker_source":"untrusted packet","input_delivery":"mailbox","missing_control":"bounds check","controlled_object":"message","security_sink":"privileged copy","concrete_effect":"isolation violation","boundary_configuration":"build:test"}
    source = root / "checkout/src/test.c";source.parent.mkdir(parents=True,exist_ok=True);source.write_text("\n".join(f"line {index}" for index in range(1,21)))
    decisive = ["not a source range"] if malformed else [{"component_id":"component:test","revision":"a"*40,"path":"src/test.c","start_line":10,"end_line":12,"content_hash":adjudication.file_hash(source)}]
    write_record(
        evidence,
        {
            "format_version": adjudication.EVIDENCE_FORMAT,
            "project_id": "project:test",
            "record_id": "record:0",
            "technical_class": decision,
            "exact_path_build_applicable": True,
            "unknowns_blocking_applicability": [],
            "proof": proof if decision != "NO_BUG" else None,
            "counterevidence": "counterexample disproves claim" if decision == "NO_BUG" else None,
            "decisive_sources": decisive,
        },
    )
    reviews = {}
    for role in ("PRIMARY", "BLIND"):
        path = root / f"{role.lower()}-review.json"
        before_hash = adjudication._row_hash(adjudication._subject_rows(root / "candidate.db", "import:current")["record:0"])
        write_record(path, {"format_version": adjudication.REVIEW_FORMAT,"project_id":"project:test","record_id":"record:0","technical_class":decision,"review_role":role,"subject_row_sha256":before_hash,"reviewer_identity":f"reviewer:{role}","reviewed_at":"2026-10-28T00:00:00Z"})
        reviews[role] = path
    dedup = root / "dedup.json"
    with sqlite3.connect(successor) as database:
        runs = [("review:primary","INDEPENDENT_REVIEWER",1),("review:blind","SAME_MODEL_REVIEW",0)] if decision == "NO_BUG" else [("review:primary","INDEPENDENT_REVIEWER",1)]
        database.executemany("INSERT INTO review_run VALUES(?,?,?,?,?,?,?,?,?,?)", [(review_id,role,"test","a"*64,None,"2026-10-28",independent,"fixture",decision,"b"*64) for review_id,role,independent in runs])
        before = adjudication._subject_rows(root / "candidate.db", "import:current")["record:0"]
        root_id = None
        if relation == "EXACT_DUPLICATE":
            root_id = "root:existing"
            database.execute("INSERT INTO campaign_record_root VALUES('record:0',?,'EXACT_DUPLICATE','EXACT')", (root_id,))
        elif relation == "RELATED_VARIANT":
            root_id = "root:new"
            database.execute("INSERT INTO root VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(root_id,"project:test","new",proof["attacker_source"],proof["input_delivery"],proof["missing_control"],proof["security_sink"],proof["concrete_effect"],proof["boundary_configuration"],decision,"d"*64,"SHA256_DECISIVE_SOURCE_MANIFEST"))
            database.execute("INSERT INTO root_fingerprint_field VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(root_id,"packet","entry","sink","check","invariant","state","primitive","none","fix","sig","a"*40,"c"*64,"e"*64))
            database.execute("INSERT INTO fingerprint VALUES('fingerprint:new',?,'invariant','{}',?)",(root_id,"e"*64))
            database.execute("INSERT INTO code_location VALUES('location:new',?,'component:test','src/test.c',10,12,?,?)",(root_id,"a"*40,"d"*64))
            database.execute("INSERT INTO call_path VALUES('path:new',?,'entry','sink','SOURCE_VERIFIED',?)",(root_id,"1"*64))
            database.execute("INSERT INTO call_edge VALUES('edge:new','path:new',0,'entry','sink','SOURCE_VERIFIED','src/test.c:10')")
            database.execute("INSERT INTO root_property_relation VALUES('property:new',?,'property:test','threat:test','boundary:test','ESTABLISHED','fixture','evidence:test',?,1)",(root_id,"d"*64))
            database.execute("INSERT INTO root_threat_assessment VALUES('assessment:new',?,'threat:test','boundary:test','attacker','entry','ESTABLISHED','fixture',?)",(root_id,adjudication.object_hash("fixture")))
            database.execute("INSERT INTO campaign_record_root VALUES('record:0',?,'RELATED_VARIANT','STRONG')",(root_id,))
        review_set = [("PRIMARY", "review:primary", {"_sha256":adjudication.file_hash(reviews["PRIMARY"])})]
        if decision == "NO_BUG": review_set.append(("BLIND", "review:blind", {"_sha256":adjudication.file_hash(reviews["BLIND"])}))
        body = {"project_id":"project:test","record_id":"record:0","root_id":root_id,"terminal_decision":decision,"proof_tuple_json":json.dumps(proof) if decision!="NO_BUG" else None,"counterevidence":"counterexample disproves claim" if decision=="NO_BUG" else None,"decisive_sources_json":json.dumps(decisive),"build_id":"build:test","configuration_hash":"c"*64,"dependency_manifest_hash":dependency_manifest_hash(successor),"review_set_hash":adjudication._review_set_hash("record:0",review_set),"reopen_conditions_json":json.dumps(["source or build evidence changes"])}
        database.execute("INSERT INTO terminal_decision_capsule VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("capsule:0",*body.values(),adjudication.object_hash(body)))
        capsule_hash=adjudication.object_hash(body)
        bindings=[("binding:primary","review:primary","SCANNER_RECORD","record:0",adjudication._row_hash(before),adjudication.file_hash(reviews["PRIMARY"])),("binding:primary:capsule","review:primary","EVIDENCE_CAPSULE","capsule:0",capsule_hash,adjudication.file_hash(reviews["PRIMARY"]))]
        if root_id == "root:new":
            root_columns=[row[1] for row in database.execute("PRAGMA table_info(root)")]
            root_values=database.execute("SELECT * FROM root WHERE root_id=?",(root_id,)).fetchone()
            root_row={"typed":adjudication._typed_row(root_columns,root_values)}
            bindings.append(("binding:primary:root","review:primary","ROOT",root_id,adjudication._row_hash(root_row),adjudication.file_hash(reviews["PRIMARY"])))
        if decision == "NO_BUG": bindings.extend([("binding:blind","review:blind","SCANNER_RECORD","record:0",adjudication._row_hash(before),adjudication.file_hash(reviews["BLIND"])),("binding:blind:capsule","review:blind","EVIDENCE_CAPSULE","capsule:0",capsule_hash,adjudication.file_hash(reviews["BLIND"]))])
        database.executemany("INSERT INTO review_binding VALUES(?,?,?,?,?,?)",bindings)
        if decision == "NO_BUG":
            audit=("audit:0","record:0","review:primary","review:blind","NO_BUG","NO_BUG","NO_BUG","SCANNER_WRONG_OBJECT_OR_API",adjudication.object_hash(decisive),"rev","build:test","c"*64,"none","AGREED","f"*64,"0"*64,"b"*64)
            database.execute("INSERT INTO fp_no_bug_audit VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", audit)
    disposition = {"kind": relation}
    if relation != "NONE":
        layers={name:["1"*64] for name in adjudication.DEDUP_LAYERS}
        write_record(dedup, {"format_version":adjudication.DEDUP_FORMAT,"project_id":"project:test","record_id":"record:0","root_id":root_id,"relation":relation,"fingerprint_hash":"f"*64 if relation=="EXACT_DUPLICATE" else "e"*64,"five_layer_dedup":{"status":"COMPLETE","layers":layers},"RCA_DISTINCT":relation!="EXACT_DUPLICATE","comparisons":{name:"MATCH" for name in adjudication.EXACT_COMPARISONS} if relation=="EXACT_DUPLICATE" else {}})
        disposition.update({"root_id": root_id,"evidence":bind(dedup)})
    result={"technical_evidence":bind(evidence),"primary_review":bind(reviews["PRIMARY"]),"primary_review_id":"review:primary","root_disposition":disposition}
    if decision == "NO_BUG": result.update({"blind_review":bind(reviews["BLIND"]),"blind_review_id":"review:blind"})
    return result


def fixture(root: Path, decision: str = "NO_BUG", relation: str = "NONE", malformed: bool = False) -> dict:
    root.mkdir()
    candidate = root / "candidate.db"
    successor = root / "successor.db"
    create_database(candidate, relation=relation)
    shutil.copy2(candidate, successor)
    with sqlite3.connect(successor) as database:
        database.execute("UPDATE campaign_subject SET technical_class=?,decision_status='TERMINAL' WHERE record_id='record:0'", (decision,))
    material = add_successor_material(root, successor, decision, relation, malformed)
    before = adjudication._subject_rows(candidate, "import:current")
    after = adjudication._subject_rows(successor, "import:current")
    records = []
    for index in range(30):
        record_id = f"record:{index}"
        entry = {"project_id":"project:test","record_id":record_id,"before_row_sha256":adjudication._row_hash(before[record_id]),"action":"ADJUDICATE" if index==0 else "RETAIN"}
        if index == 0: entry.update({"after_row_sha256":adjudication._row_hash(after[record_id]),"technical_class":decision,**material})
        records.append(entry)
    cohort = root / "cohort.json"
    write_record(cohort, {"format_version":adjudication.COHORT_FORMAT,"project_id":"project:test","scanner_population":{"import_id":"import:current","record_count":30,"record_ids_sha256":adjudication.object_hash(sorted(before)),"records":records}})
    state = root / "state"; provider = state / "stages/provider/identity"; provider.mkdir(parents=True)
    receipt_value = {"stage_id":"provider","receipt_sha256":"r"*64,"stage_identity":"s"*64,"input_sha256":"i"*64,"candidate_before":None,"candidate_after":None,"outputs":[{"locator":"output.json","sha256":"o"*64}],"status":"COMPLETE"}
    (provider/"receipt.json").write_text(json.dumps(receipt_value));(provider/"context.json").write_text("{}");(provider/"output.json").write_text("{}")
    budget = provider/"provider-budget.json";budget.write_text(json.dumps({"requests_started":4092,"requests_completed":4069,"errors":23}))
    entries=[]
    for path,kind in ((budget,"PROVIDER_BUDGET"),(provider/"receipt.json","PROVIDER_RECEIPT"),(provider/"context.json","PROVIDER_CONTEXT"),(provider/"output.json","PROVIDER_OUTPUT")):
        entries.append({"kind":kind,**bind(path)})
    inventory=root/"inventory.json";body={"format_version":state_control.INVENTORY_FORMAT,"project_id":"project:test","roots":[str(provider.resolve())],"entries":entries,"counters":{"requests_started":4092,"requests_completed":4069,"errors":23}}
    body["entries_sha256"]=adjudication.object_hash({"roots":body["roots"],"entries":entries});body["inventory_sha256"]="f"*64;write_record(inventory,body)
    policy=state/"stages/policy/old";policy.mkdir(parents=True)
    policy_value={"stage_id":"policy","receipt_sha256":"q"*64,"stage_identity":"v"*64,"input_sha256":"w"*64,"candidate_before":None,"candidate_after":None,"outputs":[],"status":"COMPLETE"}
    (policy/"receipt.json").write_text(json.dumps(policy_value));(policy/"context.json").write_text("{}")
    source_checkouts={"component:test":str((root/"checkout").resolve())};source_revisions={"component:test":"a"*40}
    profile={"project":{"project_id":"project:test","components":[{"component_id":"component:test","repository":"test","revision":"a"*40}]},"automation":{"stages":[{"stage_id":"provider","phase":"METIS_FULL_SCAN"},{"stage_id":"policy","phase":"POLICY_RECONCILIATION"}]}}
    profile_path=root/"profile.json";profile_path.write_text(json.dumps(profile))
    workflow={"format_version":"firmware-autonomous-campaign-v1","project_id":"project:test","profile_sha256":"p"*64,"candidate":adjudication._candidate_state(candidate),"stages":{"provider":"r"*64,"policy":"q"*64},"statuses":{"provider":"COMPLETE","policy":"COMPLETE"},"technical_candidate_lineage_sha256":campaign.technical_candidate_lineage(candidate),"technical_input_lineage_sha256":"t"*64,"technical_lineage_version":campaign.TECHNICAL_LINEAGE_VERSION,"execution_mode":"FULL","provider_phase_dispatches_permitted":1}
    workflow["workflow_sha256"]=adjudication.object_hash(workflow);write_record_path=state/"workflow.json";write_record_path.write_text(json.dumps(workflow,sort_keys=True))
    adjudication_path=root/"adjudication.json";adj={"format_version":adjudication.ADJUDICATION_FORMAT,"control_revision":adjudication.CONTROL_REVISION,"project_id":"project:test","base":{"candidate_sha256":adjudication.file_hash(candidate),"candidate_size":candidate.stat().st_size,"workflow_sha256":workflow["workflow_sha256"],"workflow_file_sha256":adjudication.file_hash(write_record_path),"profile_sha256":"p"*64,"technical_candidate_lineage_sha256":workflow["technical_candidate_lineage_sha256"],"technical_input_lineage_sha256":"t"*64,"provider_inventory_sha256":"f"*64,"provider_counters":body["counters"]},"cohort":bind(cohort),"prepared_successor":bind(successor),"provider_inventory":bind(inventory)};write_record(adjudication_path,adj)
    approval=root/"approval.json";write_record(approval,{"format_version":adjudication.APPROVAL_FORMAT,"authorization_type":"RECORDED_HUMAN_APPROVAL","approver_identity":"human:test","approved_at":"2026-10-28","decision":"AUTHORIZE_EXACT_DOWNSTREAM_TECHNICAL_ADJUDICATION","project_id":"project:test","adjudication_content_hash":json.loads(adjudication_path.read_text())["content_hash"],"cohort_content_hash":json.loads(cohort.read_text())["content_hash"],"cohort_file_sha256":adjudication.file_hash(cohort),"base_candidate_sha256":adjudication.file_hash(candidate),"prepared_successor_sha256":adjudication.file_hash(successor)})
    receipt={**receipt_value,"_receipt_directory":str(provider)};policy_receipt={**policy_value,"_receipt_directory":str(policy)};receipts={"provider":receipt,"policy":policy_receipt}
    return locals()


def invoke(data: dict) -> dict:
    return adjudication.apply_with_lock(adjudication_path=data["adjudication_path"],approval_path=data["approval"],project_id="project:test",project=data["root"],state=data["state"],candidate=data["candidate"],profile=data["profile"],profile_identity={"sha256":"p"*64,"locator":str(data["root"]/"profile.json")},prior_workflow={**data["workflow"],"_locator":str(data["write_record_path"])},receipts=data["receipts"],current_technical_inputs="t"*64,technical_lineage=campaign.technical_candidate_lineage,candidate_state=adjudication._candidate_state,source_checkouts=data["source_checkouts"],source_revisions=data["source_revisions"])


def refresh_bundle_bindings(data: dict) -> None:
    value=json.loads(data["adjudication_path"].read_text());value.update({"cohort":bind(data["cohort"]),"prepared_successor":bind(data["successor"])});value.pop("content_hash");write_record(data["adjudication_path"],value)
    approval=json.loads(data["approval"].read_text());approval.update({"adjudication_content_hash":json.loads(data["adjudication_path"].read_text())["content_hash"],"cohort_content_hash":json.loads(data["cohort"].read_text())["content_hash"],"cohort_file_sha256":adjudication.file_hash(data["cohort"]),"prepared_successor_sha256":adjudication.file_hash(data["successor"])});approval.pop("content_hash");write_record(data["approval"],approval)


def add_no_bug_entry(data: dict, index: int) -> dict:
    root, record_id = data["root"], f"record:{index}"
    before = adjudication._subject_rows(data["candidate"], "import:current")[record_id]
    decisive = [{"component_id":"component:test","revision":"a"*40,"path":"src/test.c","start_line":10,"end_line":12,"content_hash":adjudication.file_hash(data["root"]/"checkout/src/test.c")}]
    evidence = root / f"technical-evidence-{index}.json"
    write_record(evidence,{"format_version":adjudication.EVIDENCE_FORMAT,"project_id":"project:test","record_id":record_id,"technical_class":"NO_BUG","exact_path_build_applicable":True,"unknowns_blocking_applicability":[],"proof":None,"counterevidence":"counterexample disproves claim","decisive_sources":decisive})
    reviews = {}
    for label, role in (("primary", "PRIMARY"), ("blind", "BLIND")):
        path = root / f"{label}-review-{index}.json"
        write_record(path,{"format_version":adjudication.REVIEW_FORMAT,"project_id":"project:test","record_id":record_id,"technical_class":"NO_BUG","review_role":role,"subject_row_sha256":adjudication._row_hash(before),"reviewer_identity":f"reviewer:{label}:{index}","reviewed_at":"2026-10-28T00:00:00Z"})
        reviews[label] = path
    primary_id, blind_id = f"review:primary:{index}", f"review:blind:{index}"
    with sqlite3.connect(data["successor"]) as database:
        database.executemany("INSERT INTO review_run VALUES(?,?,?,?,?,?,?,?,?,?)",[(primary_id,"INDEPENDENT_REVIEWER","test","a"*64,None,"2026-10-28",1,"fixture","NO_BUG","b"*64),(blind_id,"SAME_MODEL_REVIEW","test","a"*64,None,"2026-10-28",0,"fixture","NO_BUG","b"*64)])
        review_set=[("PRIMARY",primary_id,{"_sha256":adjudication.file_hash(reviews["primary"])}),("BLIND",blind_id,{"_sha256":adjudication.file_hash(reviews["blind"])})]
        body={"project_id":"project:test","record_id":record_id,"root_id":None,"terminal_decision":"NO_BUG","proof_tuple_json":None,"counterevidence":"counterexample disproves claim","decisive_sources_json":json.dumps(decisive),"build_id":"build:test","configuration_hash":"c"*64,"dependency_manifest_hash":dependency_manifest_hash(data["successor"]),"review_set_hash":adjudication._review_set_hash(record_id,review_set),"reopen_conditions_json":json.dumps(["source or build evidence changes"])}
        capsule_id=f"capsule:{index}";capsule_hash=adjudication.object_hash(body)
        database.execute("INSERT INTO terminal_decision_capsule VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(capsule_id,*body.values(),capsule_hash))
        database.executemany("INSERT INTO review_binding VALUES(?,?,?,?,?,?)",[(f"binding:primary:{index}",primary_id,"SCANNER_RECORD",record_id,adjudication._row_hash(before),adjudication.file_hash(reviews["primary"])),(f"binding:primary:capsule:{index}",primary_id,"EVIDENCE_CAPSULE",capsule_id,capsule_hash,adjudication.file_hash(reviews["primary"])),(f"binding:blind:{index}",blind_id,"SCANNER_RECORD",record_id,adjudication._row_hash(before),adjudication.file_hash(reviews["blind"])),(f"binding:blind:capsule:{index}",blind_id,"EVIDENCE_CAPSULE",capsule_id,capsule_hash,adjudication.file_hash(reviews["blind"]))])
        database.execute("INSERT INTO fp_no_bug_audit VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(f"audit:{index}",record_id,primary_id,blind_id,"NO_BUG","NO_BUG","NO_BUG","SCANNER_WRONG_OBJECT_OR_API",adjudication.object_hash(decisive),"rev","build:test","c"*64,"none","AGREED","f"*64,"0"*64,"b"*64))
        database.execute("UPDATE campaign_subject SET technical_class='NO_BUG', decision_status='TERMINAL' WHERE record_id=?",(record_id,))
    after = adjudication._subject_rows(data["successor"], "import:current")[record_id]
    return {"record_id":record_id,"action":"ADJUDICATE","project_id":"project:test","technical_class":"NO_BUG","before_row_sha256":adjudication._row_hash(before),"after_row_sha256":adjudication._row_hash(after),"technical_evidence":bind(evidence),"primary_review":bind(reviews["primary"]),"primary_review_id":primary_id,"blind_review":bind(reviews["blind"]),"blind_review_id":blind_id,"root_disposition":{"kind":"NONE"}}


def add_related_entry(data: dict, index: int, root_id: str, fingerprint_hash: str) -> dict:
    record_id = f"record:{index}"
    before = adjudication._subject_rows(data["candidate"], "import:current")[record_id]
    proof = {"attacker_source":"untrusted packet","input_delivery":"mailbox","missing_control":"bounds check","controlled_object":"message","security_sink":"privileged copy","concrete_effect":"isolation violation","boundary_configuration":"build:test"}
    decisive = [{"component_id":"component:test","revision":"a"*40,"path":"src/test.c","start_line":10,"end_line":12,"content_hash":adjudication.file_hash(data["root"] / "checkout/src/test.c")}]
    evidence = data["root"] / f"technical-evidence-{index}.json"
    write_record(evidence,{"format_version":adjudication.EVIDENCE_FORMAT,"project_id":"project:test","record_id":record_id,"technical_class":"HARDENING","exact_path_build_applicable":True,"unknowns_blocking_applicability":[],"proof":proof,"counterevidence":None,"decisive_sources":decisive})
    review = data["root"] / f"primary-review-{index}.json"
    write_record(review,{"format_version":adjudication.REVIEW_FORMAT,"project_id":"project:test","record_id":record_id,"technical_class":"HARDENING","review_role":"PRIMARY","subject_row_sha256":adjudication._row_hash(before),"reviewer_identity":f"reviewer:primary:{index}","reviewed_at":"2026-10-28T00:00:00Z"})
    review_id=f"review:primary:{index}"
    dedup=data["root"]/f"dedup-{index}.json";layers={name:["1"*64] for name in adjudication.DEDUP_LAYERS}
    write_record(dedup,{"format_version":adjudication.DEDUP_FORMAT,"project_id":"project:test","record_id":record_id,"root_id":root_id,"relation":"RELATED_VARIANT","fingerprint_hash":fingerprint_hash,"five_layer_dedup":{"status":"COMPLETE","layers":layers},"RCA_DISTINCT":True,"comparisons":{}})
    with sqlite3.connect(data["successor"]) as database:
        database.execute("UPDATE campaign_subject SET technical_class='HARDENING',decision_status='TERMINAL' WHERE record_id=?",(record_id,))
        database.execute("INSERT INTO root VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(root_id,"project:test","new",proof["attacker_source"],proof["input_delivery"],proof["missing_control"],proof["security_sink"],proof["concrete_effect"],proof["boundary_configuration"],"HARDENING","d"*64,"SHA256_DECISIVE_SOURCE_MANIFEST"))
        database.execute("INSERT INTO root_fingerprint_field VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(root_id,"packet","entry","sink","check","invariant","state","primitive","none","fix","sig","a"*40,"c"*64,fingerprint_hash))
        database.execute("INSERT INTO fingerprint VALUES(?,?,?,?,?)",(f"fingerprint:{index}",root_id,"invariant","{}",fingerprint_hash))
        database.execute("INSERT INTO code_location VALUES(?,?,?,?,?,?,?,?)",(f"location:{index}",root_id,"component:test","src/test.c",10,12,"a"*40,"d"*64))
        database.execute("INSERT INTO call_path VALUES(?,?,?,?,?,?)",(f"path:{index}",root_id,"entry","sink","SOURCE_VERIFIED","1"*64))
        database.execute("INSERT INTO call_edge VALUES(?,?,?,?,?,?,?)",(f"edge:{index}",f"path:{index}",0,"entry","sink","SOURCE_VERIFIED","src/test.c:10"))
        database.execute("INSERT INTO root_property_relation VALUES(?,?,?,?,?,?,?,?,?,?)",(f"property:{index}",root_id,"property:test","threat:test","boundary:test","ESTABLISHED","fixture","evidence:test","d"*64,1))
        database.execute("INSERT INTO root_threat_assessment VALUES(?,?,?,?,?,?,?,?,?)",(f"assessment:{index}",root_id,"threat:test","boundary:test","attacker","entry","ESTABLISHED","fixture",adjudication.object_hash("fixture")))
        database.execute("INSERT INTO campaign_record_root VALUES(?,?,?,?)",(record_id,root_id,"RELATED_VARIANT","STRONG"))
        database.execute("INSERT INTO review_run VALUES(?,?,?,?,?,?,?,?,?,?)",(review_id,"INDEPENDENT_REVIEWER","test","a"*64,None,"2026-10-28",1,"fixture","HARDENING","b"*64))
        body={"project_id":"project:test","record_id":record_id,"root_id":root_id,"terminal_decision":"HARDENING","proof_tuple_json":json.dumps(proof),"counterevidence":None,"decisive_sources_json":json.dumps(decisive),"build_id":"build:test","configuration_hash":"c"*64,"dependency_manifest_hash":dependency_manifest_hash(data["successor"]),"review_set_hash":adjudication._review_set_hash(record_id,[("PRIMARY",review_id,{"_sha256":adjudication.file_hash(review)})]),"reopen_conditions_json":json.dumps(["source or build evidence changes"])}
        capsule_id=f"capsule:{index}";capsule_hash=adjudication.object_hash(body)
        database.execute("INSERT INTO terminal_decision_capsule VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(capsule_id,*body.values(),capsule_hash))
        root_columns=[row[1] for row in database.execute("PRAGMA table_info(root)")];root_values=database.execute("SELECT * FROM root WHERE root_id=?",(root_id,)).fetchone();root_hash=adjudication._row_hash({"typed":adjudication._typed_row(root_columns,root_values)})
        database.executemany("INSERT INTO review_binding VALUES(?,?,?,?,?,?)",[(f"binding:primary:{index}",review_id,"SCANNER_RECORD",record_id,adjudication._row_hash(before),adjudication.file_hash(review)),(f"binding:primary:capsule:{index}",review_id,"EVIDENCE_CAPSULE",capsule_id,capsule_hash,adjudication.file_hash(review)),(f"binding:primary:root:{index}",review_id,"ROOT",root_id,root_hash,adjudication.file_hash(review))])
    after=adjudication._subject_rows(data["successor"],"import:current")[record_id]
    return {"record_id":record_id,"action":"ADJUDICATE","project_id":"project:test","technical_class":"HARDENING","before_row_sha256":adjudication._row_hash(before),"after_row_sha256":adjudication._row_hash(after),"technical_evidence":bind(evidence),"primary_review":bind(review),"primary_review_id":review_id,"root_disposition":{"kind":"RELATED_VARIANT","root_id":root_id,"evidence":bind(dedup)}}


def test_nine_selected_records_leave_other_twenty_one_unchanged(tmp_path: Path) -> None:
    data=fixture(tmp_path/"case", "NO_BUG", "NONE")
    cohort=json.loads(data["cohort"].read_text());by_id={entry["record_id"]:entry for entry in cohort["scanner_population"]["records"]}
    for index in range(1,9):by_id[f"record:{index}"]=add_no_bug_entry(data,index)
    cohort["scanner_population"]["records"]=list(by_id.values());cohort.pop("content_hash");write_record(data["cohort"],cohort)
    value=json.loads(data["adjudication_path"].read_text());value.pop("content_hash");value["cohort"]=bind(data["cohort"]);value["prepared_successor"]=bind(data["successor"]);write_record(data["adjudication_path"],value)
    approval=json.loads(data["approval"].read_text());approval.pop("content_hash");approval.update({"adjudication_content_hash":json.loads(data["adjudication_path"].read_text())["content_hash"],"cohort_content_hash":json.loads(data["cohort"].read_text())["content_hash"],"cohort_file_sha256":adjudication.file_hash(data["cohort"]),"prepared_successor_sha256":adjudication.file_hash(data["successor"])});write_record(data["approval"],approval)
    before=adjudication._subject_rows(data["candidate"],"import:current");result=invoke(data);after=adjudication._subject_rows(data["candidate"],"import:current")
    transition=json.loads((data["state"]/"technical-adjudication-transitions"/result["transition_id"]/"transition.json").read_text())
    assert transition["candidate_delta"]["selected_count"]==9
    assert all(before[f"record:{index}"]["typed"]==after[f"record:{index}"]["typed"] for index in range(9,30))


@pytest.mark.parametrize("decision,relation", [("NO_BUG","NONE"),("VALID_VULNERABILITY","EXACT_DUPLICATE"),("HARDENING","RELATED_VARIANT")])
def test_adjudication_updates_only_selected_and_preserves_providers(tmp_path: Path, decision: str, relation: str) -> None:
    data=fixture(tmp_path/"case",decision,relation);before=data["inventory"].read_bytes();result=invoke(data);assert result["result"]=="TECHNICAL_ADJUDICATION_COMPLETED";assert data["inventory"].read_bytes()==before
    rows=adjudication._subject_rows(data["candidate"],"import:current");assert rows["record:0"]["raw"]["decision_status"]=="TERMINAL";assert all(rows[f"record:{index}"]["raw"]["technical_class"]=="DEFERRED" for index in range(1,30))
    transition=adjudication.verify_transition(data["state"],data["candidate"],data["profile"],{"sha256":"p"*64,"locator":str(data["root"]/"profile.json")},adjudication._workflow(data["state"]/"workflow.json"),data["receipts"],"t"*64,campaign.technical_candidate_lineage,data["source_checkouts"],data["source_revisions"]);assert transition["provider_inventory_after"]["counters"]=={"requests_started":4092,"requests_completed":4069,"errors":23}
    workflow=adjudication._workflow(data["state"]/"workflow.json");lineage=campaign.policy_only_technical_admission(data["profile"],{"sha256":"p"*64,"locator":str(data["profile_path"])},workflow,data["state"],data["candidate"],data["receipts"],"t"*64,source_checkouts=data["source_checkouts"]);assert lineage==transition["technical_candidate_lineage_after"]


def test_missing_review_and_unapproved_proposals_reject(tmp_path: Path) -> None:
    data=fixture(tmp_path/"case");Path(json.loads(data["cohort"].read_text())["scanner_population"]["records"][0]["blind_review"]["locator"]).unlink()
    with pytest.raises(adjudication.AdjudicationError):invoke(data)
    data=fixture(tmp_path/"nine");shutil.copy2(data["candidate"],data["successor"])
    with sqlite3.connect(data["successor"]) as database:database.execute("UPDATE campaign_subject SET technical_class='NO_BUG',decision_status='TERMINAL' WHERE CAST(substr(record_id,8) AS INTEGER)<9")
    with pytest.raises(adjudication.AdjudicationError):adjudication._validate_successor(data["candidate"],data["successor"],adjudication._record(data["cohort"],adjudication.COHORT_FORMAT,"cohort"),"project:test")


def test_changed_evidence_provider_and_unselected_record_reject(tmp_path: Path) -> None:
    data=fixture(tmp_path/"evidence")
    Path(json.loads(data["cohort"].read_text())["scanner_population"]["records"][0]["technical_evidence"]["locator"]).write_text("changed after approval")
    with pytest.raises(adjudication.AdjudicationError):invoke(data)
    assert data["candidate"].read_bytes()!=data["successor"].read_bytes()

    data=fixture(tmp_path/"provider")
    Path(data["receipt"]["_receipt_directory"],"output.json").write_text("changed")
    with pytest.raises(adjudication.AdjudicationError):invoke(data)

    data=fixture(tmp_path/"unselected")
    with sqlite3.connect(data["successor"]) as database:
        database.execute("UPDATE campaign_subject SET programme_scope='OUT_OF_SCOPE' WHERE record_id='record:1'")
    with pytest.raises(adjudication.AdjudicationError):invoke(data)


def test_interrupted_publication_recovers_exact_successor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data=fixture(tmp_path/"case");monkeypatch.setenv("FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT","AFTER_CANDIDATE")
    with pytest.raises(adjudication.AdjudicationError):invoke(data)
    monkeypatch.delenv("FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT");adjudication.recover(data["state"],data["candidate"],adjudication._candidate_state,data["source_checkouts"],data["source_revisions"]);recovered=data["candidate"].read_bytes();assert recovered==data["successor"].read_bytes();assert invoke(data)["result"]=="REUSED";assert data["candidate"].read_bytes()==recovered


def test_coordinator_mode_never_dispatches_provider(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data=fixture(tmp_path/"case");monkeypatch.setattr(campaign,"parse_bindings",lambda *_:{});monkeypatch.setattr(campaign,"source_paths",lambda *_:data["source_checkouts"]);monkeypatch.setattr(campaign,"verify_profile",lambda *_:(data["profile"],{"sha256":"p"*64,"locator":str(data["profile_path"])}));monkeypatch.setattr(campaign,"completed_receipt",lambda *_:data["receipt"]);monkeypatch.setattr(campaign,"technical_input_lineage",lambda *_:"t"*64);monkeypatch.setattr(campaign,"execute_stage",lambda *_:(_ for _ in ()).throw(AssertionError("provider dispatch")))
    args=argparse.Namespace(project_profile=data["profile_path"],candidate=str(data["candidate"]),state=str(data["state"]),source=[],source_path=[],ticket_selector=[],confluence_selector=[],credential_env=[],policy_only=False,policy_refresh_bundle=None,technical_state_correction=None,technical_state_approval=None,technical_adjudication=data["adjudication_path"],technical_adjudication_approval=data["approval"])
    assert campaign.run(args)["result"]=="TECHNICAL_ADJUDICATION_COMPLETED"


def test_real_schema_collateral_rows_and_malformed_evidence_reject(tmp_path: Path) -> None:
    data=fixture(tmp_path/"collateral")
    with sqlite3.connect(data["successor"]) as database:
        database.execute("INSERT INTO review_run VALUES(?,?,?,?,?,?,?,?,?,?)",("review:collateral","INDEPENDENT_REVIEWER","test","a"*64,None,"2026-10-28",1,"fixture","NO_BUG","b"*64))
    cohort=adjudication._record(data["cohort"],adjudication.COHORT_FORMAT,"cohort")
    with pytest.raises(adjudication.AdjudicationError,match="selected cohort"):
        adjudication._validate_successor(data["candidate"],data["successor"],cohort,"project:test")
    with sqlite3.connect(data["candidate"]) as database:
        assert database.execute("SELECT count(*) FROM campaign_subject").fetchone()[0]==51

    foreign_key=fixture(tmp_path/"foreign-key")
    with sqlite3.connect(foreign_key["successor"]) as database:
        database.executescript("CREATE TABLE fk_parent(id TEXT PRIMARY KEY);CREATE TABLE fk_child(id TEXT PRIMARY KEY,parent_id TEXT REFERENCES fk_parent(id));INSERT INTO fk_child VALUES('child','missing')")
    foreign_cohort=adjudication._record(foreign_key["cohort"],adjudication.COHORT_FORMAT,"cohort")
    with pytest.raises(adjudication.AdjudicationError,match="SQLite integrity"):
        adjudication._validate_successor(foreign_key["candidate"],foreign_key["successor"],foreign_cohort,"project:test")

    malformed=fixture(tmp_path/"malformed",malformed=True)
    original=malformed["candidate"].read_bytes()
    with pytest.raises(adjudication.AdjudicationError):
        invoke(malformed)
    assert malformed["candidate"].read_bytes()==original


@pytest.mark.parametrize("tamper",["candidate","workflow","transition","destination"])
def test_publication_preflight_rejects_before_mutation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tamper: str) -> None:
    data=fixture(tmp_path/tamper);candidate_before=data["candidate"].read_bytes();workflow_before=(data["state"]/"workflow.json").read_bytes()
    monkeypatch.setenv("FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT","BEFORE_PUBLICATION")
    with pytest.raises(adjudication.AdjudicationError):invoke(data)
    monkeypatch.delenv("FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT")
    control=next((data["state"]/"technical-adjudication-pending").iterdir())
    if tamper=="candidate": (control/"candidate-publish.db").write_bytes((control/"candidate-publish.db").read_bytes()+b"changed")
    elif tamper=="workflow": (control/"workflow-publish.json").write_bytes((control/"workflow-publish.json").read_bytes()+b"\n")
    elif tamper=="transition": (control/"transition-publish"/"approval.json").write_bytes((control/"transition-publish"/"approval.json").read_bytes()+b"\n")
    else:
        pending=json.loads((control/"pending.json").read_text());final=data["state"]/"technical-adjudication-transitions"/pending["transition_id"];final.mkdir(parents=True);(final/"conflict").write_text("conflict")
    with pytest.raises(adjudication.AdjudicationError):adjudication.recover(data["state"],data["candidate"],adjudication._candidate_state,data["source_checkouts"],data["source_revisions"])
    assert data["candidate"].read_bytes()==candidate_before and (data["state"]/"workflow.json").read_bytes()==workflow_before


def test_repeated_interruptions_and_consecutive_policy_continuation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data=fixture(tmp_path/"case");receipt_before=Path(data["receipt"]["_receipt_directory"],"receipt.json").read_bytes()
    monkeypatch.setenv("FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT","AFTER_CANDIDATE")
    with pytest.raises(adjudication.AdjudicationError):invoke(data)
    monkeypatch.setenv("FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT","AFTER_TRANSITION")
    with pytest.raises(adjudication.AdjudicationError):adjudication.recover(data["state"],data["candidate"],adjudication._candidate_state,data["source_checkouts"],data["source_revisions"])
    monkeypatch.delenv("FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT");adjudication.recover(data["state"],data["candidate"],adjudication._candidate_state,data["source_checkouts"],data["source_revisions"])
    transition=adjudication._workflow(data["state"]/"workflow.json")["technical_adjudication_transition"]
    for generation in range(2):
        with sqlite3.connect(data["candidate"]) as database:
            database.execute("INSERT INTO policy_rule_decision_binding VALUES(?,?,?,?)",(f"policy:{generation}","root:policy","IN_SCOPE",f"hash:{generation}"))
        prior=adjudication._workflow(data["state"]/"workflow.json")
        workflow={key:value for key,value in prior.items() if not key.startswith("_") and key!="workflow_sha256"}
        workflow.update({"candidate":adjudication._candidate_state(data["candidate"]),"execution_mode":"POLICY_ONLY","provider_phase_dispatches_permitted":0,"base_workflow_sha256":prior["workflow_sha256"],"technical_adjudication_transition":transition})
        workflow["workflow_sha256"]=adjudication.object_hash(workflow);(data["state"]/"workflow.json").write_text(json.dumps(workflow,sort_keys=True))
        receipts={"provider":data["receipt"],"policy":{**data["policy_receipt"],"receipt_sha256":f"{generation+1}"*64}}
        adjudication.verify_transition(data["state"],data["candidate"],data["profile"],{"sha256":"p"*64,"locator":str(data["profile_path"])},adjudication._workflow(data["state"]/"workflow.json"),receipts,"t"*64,campaign.technical_candidate_lineage,data["source_checkouts"],data["source_revisions"])
    assert Path(data["receipt"]["_receipt_directory"],"receipt.json").read_bytes()==receipt_before


def test_terminal_source_and_dedup_contracts_reject_before_mutation(tmp_path: Path) -> None:
    changed=fixture(tmp_path/"changed-source","VALID_VULNERABILITY","EXACT_DUPLICATE");before=changed["candidate"].read_bytes();(changed["root"]/"checkout/src/test.c").write_text("changed")
    with pytest.raises(adjudication.AdjudicationError,match="source bytes"):invoke(changed)
    assert changed["candidate"].read_bytes()==before

    incomplete=fixture(tmp_path/"incomplete-dedup","VALID_VULNERABILITY","EXACT_DUPLICATE");dedup=incomplete["root"]/"dedup.json";value=json.loads(dedup.read_text());value={key:item for key,item in value.items() if key not in {"content_hash","five_layer_dedup","comparisons"}};write_record(dedup,value);cohort=json.loads(incomplete["cohort"].read_text());cohort["scanner_population"]["records"][0]["root_disposition"]["evidence"]=bind(dedup);cohort.pop("content_hash");write_record(incomplete["cohort"],cohort)
    with pytest.raises(adjudication.AdjudicationError,match="five-layer"):adjudication._validate_successor(incomplete["candidate"],incomplete["successor"],adjudication._record(incomplete["cohort"],adjudication.COHORT_FORMAT,"cohort"),"project:test",incomplete["source_checkouts"],incomplete["source_revisions"])


def test_empty_proof_tuple_rejects(tmp_path: Path) -> None:
    data=fixture(tmp_path/"case","VALID_VULNERABILITY","EXACT_DUPLICATE");evidence_path=data["root"]/"technical-evidence.json";evidence=json.loads(evidence_path.read_text());evidence["proof"]["security_sink"]="";evidence.pop("content_hash");write_record(evidence_path,evidence);cohort=json.loads(data["cohort"].read_text());cohort["scanner_population"]["records"][0]["technical_evidence"]=bind(evidence_path);cohort.pop("content_hash");write_record(data["cohort"],cohort)
    with pytest.raises(adjudication.AdjudicationError,match="incomplete proof"):adjudication._validate_successor(data["candidate"],data["successor"],adjudication._record(data["cohort"],adjudication.COHORT_FORMAT,"cohort"),"project:test",data["source_checkouts"],data["source_revisions"])


@pytest.mark.parametrize("field,value", [("configuration_hash", "9"*64), ("dependency_manifest_hash", "8"*64), ("dependency_manifest_hash", "invalid")])
def test_terminal_capsule_binds_build_and_dependency_manifest(tmp_path: Path, field: str, value: str) -> None:
    data=fixture(tmp_path/field,"VALID_VULNERABILITY","EXACT_DUPLICATE")
    with sqlite3.connect(data["successor"]) as database:
        columns=[row[1] for row in database.execute("PRAGMA table_info(terminal_decision_capsule)")]
        capsule=dict(zip(columns,database.execute("SELECT * FROM terminal_decision_capsule WHERE record_id='record:0'").fetchone()))
        capsule[field]=value
        capsule["content_hash"]=adjudication.object_hash({key:item for key,item in capsule.items() if key not in {"capsule_id","content_hash"}})
        database.execute(f"UPDATE terminal_decision_capsule SET {field}=?,content_hash=? WHERE record_id='record:0'",(value,capsule["content_hash"]))
        database.execute("UPDATE review_binding SET subject_hash=? WHERE subject_kind='EVIDENCE_CAPSULE' AND subject_id='capsule:0'",(capsule["content_hash"],))
    before=data["candidate"].read_bytes();refresh_bundle_bindings(data)
    with pytest.raises(adjudication.AdjudicationError,match="build|dependency"):invoke(data)
    assert data["candidate"].read_bytes()==before


def test_new_root_dedup_fingerprint_is_bound_to_that_root(tmp_path: Path) -> None:
    data=fixture(tmp_path/"case","HARDENING","RELATED_VARIANT")
    cohort=json.loads(data["cohort"].read_text())
    cohort["scanner_population"]["records"][1]=add_related_entry(data,1,"root:other","a"*64)
    wrong=data["root"]/"dedup.json";dedup=json.loads(wrong.read_text());dedup["fingerprint_hash"]="a"*64;dedup.pop("content_hash");write_record(wrong,dedup)
    cohort["scanner_population"]["records"][0]["root_disposition"]["evidence"]=bind(wrong)
    cohort.pop("content_hash");write_record(data["cohort"],cohort)
    before=data["candidate"].read_bytes();refresh_bundle_bindings(data)
    with pytest.raises(adjudication.AdjudicationError,match="promoted root fingerprint"):invoke(data)
    assert data["candidate"].read_bytes()==before


def policy_generation(data: dict) -> dict:
    workflow=adjudication._workflow(data["state"]/"workflow.json")
    value={key:item for key,item in workflow.items() if not key.startswith("_") and key not in {"workflow_sha256"}}
    value.update({"base_workflow_sha256":workflow["workflow_sha256"],"execution_mode":"POLICY_ONLY","provider_phase_dispatches_permitted":0})
    value["workflow_sha256"]=adjudication.object_hash(value)
    (data["state"]/"workflow.json").write_text(json.dumps(value,sort_keys=True))
    return adjudication._workflow(data["state"]/"workflow.json")


def followup_adjudication(data: dict, index: int) -> dict:
    next_data=dict(data);next_data["workflow"]=adjudication._workflow(data["state"]/"workflow.json");next_data["write_record_path"]=data["state"]/"workflow.json"
    next_data["successor"]=data["root"]/f"successor-{index}.db";shutil.copy2(data["candidate"],next_data["successor"])
    selected=add_no_bug_entry(next_data,index);before=adjudication._subject_rows(data["candidate"],"import:current");after=adjudication._subject_rows(next_data["successor"],"import:current")
    records=[]
    for record_id,row in before.items():
        entry={"project_id":"project:test","record_id":record_id,"before_row_sha256":adjudication._row_hash(row),"action":"ADJUDICATE" if record_id==selected["record_id"] else "RETAIN"}
        if record_id==selected["record_id"]:entry.update(selected)
        records.append(entry)
    next_data["cohort"]=data["root"]/f"cohort-{index}.json";write_record(next_data["cohort"],{"format_version":adjudication.COHORT_FORMAT,"project_id":"project:test","scanner_population":{"import_id":"import:current","record_count":len(records),"record_ids_sha256":adjudication.object_hash(sorted(before)),"records":records}})
    base={"candidate_sha256":adjudication.file_hash(data["candidate"]),"candidate_size":data["candidate"].stat().st_size,"workflow_sha256":next_data["workflow"]["workflow_sha256"],"workflow_file_sha256":adjudication.file_hash(next_data["write_record_path"]),"profile_sha256":"p"*64,"technical_candidate_lineage_sha256":campaign.technical_candidate_lineage(data["candidate"]),"technical_input_lineage_sha256":"t"*64,"provider_inventory_sha256":"f"*64,"provider_counters":{"requests_started":4092,"requests_completed":4069,"errors":23}}
    next_data["adjudication_path"]=data["root"]/f"adjudication-{index}.json";write_record(next_data["adjudication_path"],{"format_version":adjudication.ADJUDICATION_FORMAT,"control_revision":adjudication.CONTROL_REVISION,"project_id":"project:test","base":base,"cohort":bind(next_data["cohort"]),"prepared_successor":bind(next_data["successor"]),"provider_inventory":bind(data["inventory"])})
    next_data["approval"]=data["root"]/f"approval-{index}.json";write_record(next_data["approval"],{"format_version":adjudication.APPROVAL_FORMAT,"authorization_type":"RECORDED_HUMAN_APPROVAL","approver_identity":"human:test","approved_at":"2026-10-28","decision":"AUTHORIZE_EXACT_DOWNSTREAM_TECHNICAL_ADJUDICATION","project_id":"project:test","adjudication_content_hash":json.loads(next_data["adjudication_path"].read_text())["content_hash"],"cohort_content_hash":json.loads(next_data["cohort"].read_text())["content_hash"],"cohort_file_sha256":adjudication.file_hash(next_data["cohort"]),"base_candidate_sha256":adjudication.file_hash(data["candidate"]),"prepared_successor_sha256":adjudication.file_hash(next_data["successor"])})
    return next_data


def apply_unstubbed_h43(data: dict) -> None:
    retained=data["root"]/"h43-retained.json";retained.write_text("retained\n");evidence={}
    for purpose in state_control.REQUIRED_BLOCKERS:
        path=data["root"]/f"h43-{purpose}.json";path.write_text(json.dumps({"purpose":purpose}));evidence[purpose]=path
    with sqlite3.connect(data["candidate"]) as database:
        database.executescript("CREATE TABLE validation_run(validation_run_id TEXT PRIMARY KEY,project_id TEXT,authorization_status TEXT,reproduction_level TEXT,rca_workflow_status TEXT,authorization_workflow_status TEXT,reproduction_workflow_status TEXT,workflow_blocker TEXT);CREATE TABLE validation_run_root(validation_run_id TEXT,root_id TEXT);CREATE TABLE policy_technical_reopen_queue(queue_id TEXT PRIMARY KEY,root_id TEXT,trigger_kind TEXT,evidence_locator TEXT,evidence_hash TEXT,affected_axes_json TEXT,rationale TEXT,status TEXT,resolution_evidence_locator TEXT,resolution_evidence_hash TEXT,resolution_rationale TEXT,resolution_content_hash TEXT,content_hash TEXT);")
        database.execute("INSERT INTO validation_run VALUES(?,?,?,?,?,?,?,?)",("validation:TFM-ROOT-H43PTPSY","project:test","NOT_REQUESTED","NOT_REPRODUCED","NOT_APPLICABLE","NOT_APPLICABLE","NOT_APPLICABLE",None));database.execute("INSERT INTO validation_run_root VALUES(?,?)",("validation:TFM-ROOT-H43PTPSY","TFM-ROOT-H43PTPSY"))
        for index in range(8):
            row={"queue_id":"","root_id":f"other:{index}","trigger_kind":"EXACT_DUPLICATE_OR_VARIANT","evidence_locator":str(retained),"evidence_hash":adjudication.file_hash(retained),"affected_axes_json":'["DEDUPLICATION"]',"rationale":f"retained {index}","status":"QUEUED","resolution_evidence_locator":None,"resolution_evidence_hash":None,"resolution_rationale":None,"resolution_content_hash":None};row["content_hash"]=adjudication.object_hash({k:v for k,v in row.items() if k not in {"queue_id","content_hash"}});row["queue_id"]=f"v68:reopen:{row['content_hash'][:24]}";database.execute(f"INSERT INTO policy_technical_reopen_queue VALUES({','.join('?' for _ in row)})",tuple(row.values()))
        columns=[row[1] for row in database.execute("PRAGMA table_info(validation_run)")];before=dict(zip(columns,database.execute("SELECT * FROM validation_run").fetchone()));queue_columns=[row[1] for row in database.execute("PRAGMA table_info(policy_technical_reopen_queue)")]
    workflow={k:v for k,v in adjudication._workflow(data["state"]/"workflow.json").items() if not k.startswith("_") and k!="workflow_sha256"};workflow.update({"candidate":adjudication._candidate_state(data["candidate"]),"technical_candidate_lineage_sha256":campaign.technical_candidate_lineage(data["candidate"]),"execution_mode":"POLICY_ONLY","provider_phase_dispatches_permitted":0});workflow["workflow_sha256"]=adjudication.object_hash(workflow);data["write_record_path"].write_text(json.dumps(workflow,sort_keys=True));data["workflow"]={**workflow,"_locator":str(data["write_record_path"])}
    blocker=json.dumps({p:{"locator":str(f),"sha256":adjudication.file_hash(f)} for p,f in evidence.items()},sort_keys=True,separators=(",",":"));after={**before,"rca_workflow_status":"BLOCKED","authorization_workflow_status":"BLOCKED","reproduction_workflow_status":"BLOCKED","workflow_blocker":blocker};queue_body={"root_id":"TFM-ROOT-H43PTPSY","trigger_kind":"EXACT_DUPLICATE_OR_VARIANT","evidence_locator":str(evidence["RCA"]),"evidence_hash":adjudication.file_hash(evidence["RCA"]),"affected_axes_json":'["DEDUPLICATION","REPRODUCTION"]',"rationale":"test-only","status":"QUEUED","resolution_evidence_locator":None,"resolution_evidence_hash":None,"resolution_rationale":None,"resolution_content_hash":None};digest=adjudication.object_hash(queue_body);queue={"queue_id":f"v68:reopen:{digest[:24]}",**queue_body,"content_hash":digest};prepared=data["root"]/"h43-successor.db";shutil.copy2(data["candidate"],prepared);state_control._apply_database(prepared,{"target":{"root_id":"TFM-ROOT-H43PTPSY","validation_run_id":"validation:TFM-ROOT-H43PTPSY"},"validation_run_after":after,"queue_addition":queue,"base":{"unresolved_queue_count":8}},columns,queue_columns)
    counters=json.loads(data["budget"].read_text());body={"format_version":state_control.CORRECTION_FORMAT,"control_revision":state_control.CONTROL_REVISION,"project_id":"project:test","base":{"candidate":adjudication._candidate_state(data["candidate"]),"workflow_sha256":workflow["workflow_sha256"],"workflow_file_sha256":adjudication.file_hash(data["write_record_path"]),"profile_sha256":"p"*64,"technical_candidate_lineage_sha256":campaign.technical_candidate_lineage(data["candidate"]),"technical_input_lineage_sha256":"t"*64,"provider_inventory_sha256":"f"*64,"provider_counters":counters,"unresolved_queue_count":8},"target":{"root_id":"TFM-ROOT-H43PTPSY","validation_run_id":"validation:TFM-ROOT-H43PTPSY"},"validation_run_before":before,"validation_run_after":after,"queue_addition":queue,"evidence":[{"purpose":p,"locator":str(f),"sha256":adjudication.file_hash(f),"size":f.stat().st_size} for p,f in evidence.items()],"provider_inventory":bind(data["inventory"]),"provider_invariants_after":{"inventory_sha256":"f"*64,"counters":counters},"technical_candidate_lineage_after":campaign.technical_candidate_lineage(prepared)};correction=data["root"]/"h43-correction.json";write_record(correction,body);record=data["root"]/"h43-authorization.txt";record.write_text("test-only authorization\n");approval=data["root"]/"h43-approval.json";write_record(approval,{"format_version":state_control.APPROVAL_FORMAT,"control_revision":state_control.CONTROL_REVISION,"project_id":"project:test","decision":"APPROVE_EXACT_TECHNICAL_STATE_CORRECTION","correction_content_hash":json.loads(correction.read_text())["content_hash"],"authorized_by":"fixture","authority":"test-only","approval_id":"h43:test","authorization_record":bind(record)})
    state_control.apply_with_lock(correction_path=correction,approval_path=approval,project_id="project:test",project=data["root"],state=data["state"],candidate=data["candidate"],profile=data["profile"],profile_identity={"sha256":"p"*64,"locator":str(data["profile_path"])},prior_workflow=data["workflow"],receipts=data["receipts"],current_technical_inputs="t"*64,technical_lineage=campaign.technical_candidate_lineage,candidate_state=adjudication._candidate_state)


def test_two_adjudications_compose_with_h43_and_policy_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data=fixture(tmp_path/"case");fake={"transition_id":"h43","locator":"retained","sha256":"a"*64};data["workflow"]["technical_state_transition"]=fake;data["workflow"].pop("workflow_sha256");data["workflow"]["workflow_sha256"]=adjudication.object_hash(data["workflow"]);data["write_record_path"].write_text(json.dumps(data["workflow"],sort_keys=True));base=json.loads(data["adjudication_path"].read_text());base["base"].update({"workflow_sha256":data["workflow"]["workflow_sha256"],"workflow_file_sha256":adjudication.file_hash(data["write_record_path"])});base.pop("content_hash");write_record(data["adjudication_path"],base);approval=json.loads(data["approval"].read_text());approval["adjudication_content_hash"]=base["content_hash"];approval.pop("content_hash");write_record(data["approval"],approval)
    expected_h43_lineage=data["workflow"]["technical_candidate_lineage_sha256"]
    calls=[]
    def verify_h43(*_args,descendant_base=None,**_kwargs):
        calls.append(descendant_base)
        if descendant_base["technical_candidate_lineage_sha256"]!=expected_h43_lineage:raise state_control.CorrectionError("technical-state transition descendant candidate differs")
        return {"transition_id":"h43"}
    monkeypatch.setattr(state_control,"verify_transition",verify_h43)
    first=invoke(data);policy_generation(data)
    second=followup_adjudication(data,1);invoke(second);policy_generation(data)
    adjudication.verify_transition(data["state"],data["candidate"],data["profile"],{"sha256":"p"*64,"locator":str(data["profile_path"])},adjudication._workflow(data["state"]/"workflow.json"),data["receipts"],"t"*64,campaign.technical_candidate_lineage,data["source_checkouts"],data["source_revisions"])
    assert calls and all(call["technical_candidate_lineage_sha256"]==expected_h43_lineage for call in calls)
    predecessor_approval=data["state"] / "technical-adjudication-transitions" / first["transition_id"] / "approval.json"
    predecessor_approval.write_text(predecessor_approval.read_text()+"\n")
    with pytest.raises(adjudication.AdjudicationError,match="bytes changed"):
        adjudication.verify_transition(data["state"],data["candidate"],data["profile"],{"sha256":"p"*64,"locator":str(data["profile_path"])},adjudication._workflow(data["state"]/"workflow.json"),data["receipts"],"t"*64,campaign.technical_candidate_lineage,data["source_checkouts"],data["source_revisions"])


def test_predecessor_transition_is_composed_after_adjudication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data=fixture(tmp_path/"case");fake={"transition_id":"h43","locator":"retained","sha256":"a"*64};data["workflow"]["technical_state_transition"]=fake;data["workflow"].pop("workflow_sha256");data["workflow"]["workflow_sha256"]=adjudication.object_hash(data["workflow"]);data["write_record_path"].write_text(json.dumps(data["workflow"],sort_keys=True));base=json.loads(data["adjudication_path"].read_text());base["base"].update({"workflow_sha256":data["workflow"]["workflow_sha256"],"workflow_file_sha256":adjudication.file_hash(data["write_record_path"])});base.pop("content_hash");write_record(data["adjudication_path"],base);approval=json.loads(data["approval"].read_text());approval["adjudication_content_hash"]=base["content_hash"];approval.pop("content_hash");write_record(data["approval"],approval);invoke(data)
    def reject(*_args,**_kwargs):raise state_control.CorrectionError("H43 approval chain changed")
    monkeypatch.setattr(state_control,"verify_transition",reject)
    with pytest.raises(adjudication.AdjudicationError,match="H43 approval"):
        adjudication.verify_transition(data["state"],data["candidate"],data["profile"],{"sha256":"p"*64,"locator":str(data["profile_path"])},adjudication._workflow(data["state"]/"workflow.json"),data["receipts"],"t"*64,campaign.technical_candidate_lineage,data["source_checkouts"],data["source_revisions"])


def test_followup_adjudication_rejects_changed_predecessor_before_publication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data=fixture(tmp_path/"case");fake={"transition_id":"h43","locator":"retained","sha256":"a"*64};data["workflow"]["technical_state_transition"]=fake;data["workflow"].pop("workflow_sha256");data["workflow"]["workflow_sha256"]=adjudication.object_hash(data["workflow"]);data["write_record_path"].write_text(json.dumps(data["workflow"],sort_keys=True));base=json.loads(data["adjudication_path"].read_text());base["base"].update({"workflow_sha256":data["workflow"]["workflow_sha256"],"workflow_file_sha256":adjudication.file_hash(data["write_record_path"])});base.pop("content_hash");write_record(data["adjudication_path"],base);approval=json.loads(data["approval"].read_text());approval["adjudication_content_hash"]=base["content_hash"];approval.pop("content_hash");write_record(data["approval"],approval)
    monkeypatch.setattr(state_control,"verify_transition",lambda *_args,**_kwargs:{"transition_id":"h43"})
    first=invoke(data);policy_generation(data);second=followup_adjudication(data,1)
    predecessor_approval=data["state"] / "technical-adjudication-transitions" / first["transition_id"] / "approval.json";predecessor_approval.write_text(predecessor_approval.read_text()+"\n")
    before_candidate=data["candidate"].read_bytes();before_workflow=(data["state"] / "workflow.json").read_bytes()
    with pytest.raises(adjudication.AdjudicationError,match="bytes changed"):invoke(second)
    assert data["candidate"].read_bytes()==before_candidate and (data["state"] / "workflow.json").read_bytes()==before_workflow


def test_unstubbed_h43_adjudication_policy_adjudication_policy_chain(tmp_path: Path) -> None:
    data=fixture(tmp_path/"case");apply_unstubbed_h43(data);data["workflow"]=adjudication._workflow(data["state"]/"workflow.json");data["write_record_path"]=data["state"]/"workflow.json"
    first=followup_adjudication(data,0);invoke(first);policy_generation(data);adjudication.verify_transition(data["state"],data["candidate"],data["profile"],{"sha256":"p"*64,"locator":str(data["profile_path"])},adjudication._workflow(data["state"]/"workflow.json"),data["receipts"],"t"*64,campaign.technical_candidate_lineage,data["source_checkouts"],data["source_revisions"])
    second=followup_adjudication(data,1);invoke(second);policy_generation(data);adjudication.verify_transition(data["state"],data["candidate"],data["profile"],{"sha256":"p"*64,"locator":str(data["profile_path"])},adjudication._workflow(data["state"]/"workflow.json"),data["receipts"],"t"*64,campaign.technical_candidate_lineage,data["source_checkouts"],data["source_revisions"])
    assert first["cohort"] != second["cohort"]


@pytest.mark.parametrize("phase",["PREPARATION_DIRECTORY_CREATED","PREPARATION_PUBLICATION_DIRECTORY_CREATED","PREPARATION_PREDECESSOR_COPIED","PREPARATION_SUCCESSOR_COPIED","PREPARATION_WORKFLOW_COPIED","PREPARATION_EVIDENCE_COPIED","PREPARATION_TRANSITION_WRITTEN","PREPARATION_SUCCESSOR_WORKFLOW_WRITTEN"])
def test_interruption_during_preparation_preserves_and_retries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str) -> None:
    data=fixture(tmp_path/phase);before=data["candidate"].read_bytes();monkeypatch.setenv("FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT",phase)
    with pytest.raises(adjudication.AdjudicationError):invoke(data)
    assert data["candidate"].read_bytes()==before
    monkeypatch.delenv("FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT");adjudication.recover(data["state"],data["candidate"],adjudication._candidate_state,data["source_checkouts"],data["source_revisions"])
    assert next((data["state"]/"technical-adjudication-incomplete").iterdir()).is_dir()
    assert invoke(data)["result"]=="TECHNICAL_ADJUDICATION_COMPLETED"


@pytest.mark.parametrize(
    "artifact,decision,relation",
    [
        ("technical_evidence", "NO_BUG", "NONE"),
        ("primary_review", "NO_BUG", "NONE"),
        ("deduplication", "VALID_VULNERABILITY", "EXACT_DUPLICATE"),
        ("provider_output", "NO_BUG", "NONE"),
        ("provider_receipt", "NO_BUG", "NONE"),
        ("provider_checkpoint", "NO_BUG", "NONE"),
    ],
)
def test_recovery_reopens_external_prerequisites_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact: str,
    decision: str,
    relation: str,
) -> None:
    data = fixture(tmp_path / artifact, decision, relation)
    before_candidate = data["candidate"].read_bytes()
    before_workflow = (data["state"] / "workflow.json").read_bytes()
    monkeypatch.setenv(
        "FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT", "BEFORE_PUBLICATION"
    )
    with pytest.raises(adjudication.AdjudicationError):
        invoke(data)
    monkeypatch.delenv("FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT")
    paths = {
        "technical_evidence": Path(data["material"]["technical_evidence"]["locator"]),
        "primary_review": Path(data["material"]["primary_review"]["locator"]),
        "provider_output": data["provider"] / "output.json",
        "provider_receipt": data["provider"] / "receipt.json",
        "provider_checkpoint": data["provider"] / "provider-budget.json",
    }
    if artifact == "deduplication":
        paths[artifact] = Path(data["material"]["root_disposition"]["evidence"]["locator"])
    paths[artifact].write_bytes(paths[artifact].read_bytes() + b"changed")
    with pytest.raises(adjudication.AdjudicationError, match="external prerequisite changed"):
        adjudication.recover(
            data["state"], data["candidate"], adjudication._candidate_state,
            data["source_checkouts"], data["source_revisions"],
        )
    assert data["candidate"].read_bytes() == before_candidate
    assert (data["state"] / "workflow.json").read_bytes() == before_workflow


def test_recovery_reopens_predecessor_transition_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = fixture(tmp_path / "case")
    first = invoke(data)
    policy_generation(data)
    second = followup_adjudication(data, 1)
    monkeypatch.setenv(
        "FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT", "BEFORE_PUBLICATION"
    )
    with pytest.raises(adjudication.AdjudicationError):
        invoke(second)
    monkeypatch.delenv("FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT")
    before_candidate = data["candidate"].read_bytes()
    before_workflow = (data["state"] / "workflow.json").read_bytes()
    predecessor_approval = (
        data["state"] / "technical-adjudication-transitions"
        / first["transition_id"] / "approval.json"
    )
    predecessor_approval.write_bytes(predecessor_approval.read_bytes() + b"changed")
    with pytest.raises(adjudication.AdjudicationError, match="external prerequisite changed"):
        adjudication.recover(
            data["state"], data["candidate"], adjudication._candidate_state,
            data["source_checkouts"], data["source_revisions"],
        )
    assert data["candidate"].read_bytes() == before_candidate
    assert (data["state"] / "workflow.json").read_bytes() == before_workflow


@pytest.mark.parametrize("changed_ancestor", [None, "approval", "technical_evidence"])
def test_recovery_reopens_every_ancestor_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changed_ancestor: str | None,
) -> None:
    data = fixture(tmp_path / str(changed_ancestor))
    first = invoke(data)
    policy_generation(data)
    invoke(followup_adjudication(data, 1))
    policy_generation(data)
    third = followup_adjudication(data, 2)
    monkeypatch.setenv(
        "FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT", "BEFORE_PUBLICATION"
    )
    with pytest.raises(adjudication.AdjudicationError):
        invoke(third)
    monkeypatch.delenv("FIRMWARE_TEST_TECHNICAL_ADJUDICATION_INTERRUPT")
    before_candidate = data["candidate"].read_bytes()
    before_workflow = (data["state"] / "workflow.json").read_bytes()
    if changed_ancestor == "approval":
        changed = (
            data["state"] / "technical-adjudication-transitions"
            / first["transition_id"] / "approval.json"
        )
    elif changed_ancestor == "technical_evidence":
        changed = Path(data["material"]["technical_evidence"]["locator"])
    else:
        adjudication.recover(
            data["state"], data["candidate"], adjudication._candidate_state,
            data["source_checkouts"], data["source_revisions"],
        )
        assert data["candidate"].read_bytes() == third["successor"].read_bytes()
        return
    changed.write_bytes(changed.read_bytes() + b"changed")
    with pytest.raises(adjudication.AdjudicationError, match="external prerequisite changed"):
        adjudication.recover(
            data["state"], data["candidate"], adjudication._candidate_state,
            data["source_checkouts"], data["source_revisions"],
        )
    assert data["candidate"].read_bytes() == before_candidate
    assert (data["state"] / "workflow.json").read_bytes() == before_workflow
