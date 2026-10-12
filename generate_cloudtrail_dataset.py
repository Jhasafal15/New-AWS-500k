"""
High-Performance Generator for the 500,000-Row Synthetic CloudTrail Dataset.
Generates realistic normal, suspicious, and anomalous events with multi-event behavioral sequences.
"""

import json
import uuid
import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Any

import numpy as np
import pandas as pd

from .config import (
    RANDOM_SEED,
    DEFAULT_ROW_COUNT,
    SCENARIO_TARGET_COUNTS,
    SYNTHETIC_ACCOUNT_ID,
    AWS_REGIONS,
    SENSITIVE_EVENTS,
    PRIVILEGE_ESCALATION_EVENTS,
    WRITE_PREFIXES,
    CLOUDTRAIL_CSV,
    CLOUDTRAIL_JSONL,
    SYNTHETIC_DIR,
)
from .scenarios import (
    IDENTITIES,
    IP_POOLS,
    USER_AGENTS,
    EVENT_TO_SERVICE,
    CORRELATED_SEQUENCE_TEMPLATES,
)
from .features import (
    compute_all_behavioral_features,
    build_risk_reasons,
    get_recommended_action_text,
)

# Set global deterministic random seed
np.random.seed(RANDOM_SEED)


def get_api_category(event_name: str) -> str:
    """Classify API into category matching feature_extractor.py."""
    name_lower = event_name.lower()
    if any(k in name_lower for k in ["delete", "terminate", "remove", "detach", "disassociate"]):
        return "delete"
    if any(k in name_lower for k in ["policy", "permission", "role", "user", "group", "access"]):
        return "permission"
    if any(k in name_lower for k in ["create", "put", "update", "modify", "attach", "associate", "start", "run", "launch"]):
        return "write"
    if any(k in name_lower for k in ["get", "describe", "list", "head"]):
        return "read"
    return "other"


def is_privileged_api_check(event_name: str) -> bool:
    """Check privileged API matching feature_extractor.py."""
    sensitive_ops = {
        "CreateUser", "DeleteUser", "CreateRole", "DeleteRole",
        "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
        "CreateAccessKey", "DeleteAccessKey", "RunInstances", "TerminateInstances",
        "ModifyInstanceAttribute", "PutBucketPolicy", "DeleteBucketPolicy",
        "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress"
    }
    return event_name in sensitive_ops


def generate_time_window(start_dt: datetime.datetime, end_dt: datetime.datetime, count: int) -> List[datetime.datetime]:
    """Generate sorted timestamps within a date range."""
    start_ts = start_dt.timestamp()
    end_ts = end_dt.timestamp()
    random_ts = np.random.uniform(start_ts, end_ts, size=count)
    random_ts.sort()
    return [datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc) for ts in random_ts]


class CloudTrailDatasetGenerator:
    """
    Constructs 500,000 synthetic AWS CloudTrail behavioral security events.
    """

    def __init__(self, total_rows: int = DEFAULT_ROW_COUNT, seed: int = RANDOM_SEED):
        self.total_rows = total_rows
        self.seed = seed
        np.random.seed(seed)
        SYNTHETIC_DIR.mkdir(parents=True, exist_ok=True)

        self.start_date = datetime.datetime(2026, 6, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
        self.end_date = datetime.datetime(2026, 9, 28, 23, 59, 59, tzinfo=datetime.timezone.utc)
        self.sequence_counter = 1
        self.session_counter = 1

    def _create_event_dict(
        self,
        dt: datetime.datetime,
        event_name: str,
        identity_name: str,
        source_ip: str,
        user_agent_key: str,
        error_code: str = "",
        error_message: str = "",
        mfa_value: str = "true",
        session_id: str = "",
        behavior_sequence_id: str = "",
        behavior_label: str = "NORMAL",
        attack_scenario: str = "NORMAL_BEHAVIOR",
        region: str = "us-east-1",
    ) -> Dict[str, Any]:
        """Creates a single CloudTrail record dictionary with full fidelity."""
        ident_info = IDENTITIES[identity_name]
        event_source = EVENT_TO_SERVICE.get(event_name, "sts.amazonaws.com")
        user_agent = USER_AGENTS.get(user_agent_key, USER_AGENTS["console"])

        is_failed = bool(error_code or error_message)
        read_only = str(not (event_name.startswith(WRITE_PREFIXES) or is_privileged_api_check(event_name)))

        hour = dt.hour
        is_night = (hour < 6 or hour >= 22)
        day_name = dt.strftime("%A")

        is_anomaly = -1 if behavior_label in ["ANOMALOUS", "SUSPICIOUS"] else 1
        anomaly_label = "ANOMALY" if is_anomaly == -1 else "NORMAL"

        return {
            "event_time": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_name": event_name,
            "event_source": event_source,
            "aws_region": region,
            "source_ip": source_ip,
            "user_agent": user_agent,
            "user_type": ident_info["user_type"],
            "user_name": identity_name,
            "principal_id": ident_info["principal_id"],
            "access_key_id": ident_info["access_key_id"],
            "user_arn": ident_info["arn"],
            "mfa_used": mfa_value,
            "error_code": error_code,
            "error_message": error_message,
            "is_failed": is_failed,
            "error_present": is_failed,
            "read_only": read_only,
            "recipient_account_id": SYNTHETIC_ACCOUNT_ID,
            "event_hour": hour,
            "event_day": day_name,
            "is_night": is_night,
            "api_category": get_api_category(event_name),
            "is_privileged_api": is_privileged_api_check(event_name),
            # Sequence & Session Metadata
            "session_id": session_id,
            "activity_group_id": f"GRP_{session_id.split('_')[-1]}",
            "behavior_sequence_id": behavior_sequence_id,
            "principal_session_id": f"PSES_{identity_name[:6]}_{session_id.split('_')[-1]}",
            # Ground-Truth Labels
            "behavior_label": behavior_label,
            "attack_scenario": attack_scenario,
            "is_anomaly": is_anomaly,
            "anomaly_label": anomaly_label,
        }

    def generate_all_events(self) -> List[Dict[str, Any]]:
        """
        Orchestrates event generation according to target scenario distributions.
        """
        events: List[Dict[str, Any]] = []
        target_counts = dict(SCENARIO_TARGET_COUNTS)

        # Scale proportionally if total_rows differs from default 500,000
        if self.total_rows != DEFAULT_ROW_COUNT:
            scale = self.total_rows / DEFAULT_ROW_COUNT
            target_counts = {k: int(v * scale) for k, v in target_counts.items()}
            # Adjust rounding difference
            diff = self.total_rows - sum(target_counts.values())
            target_counts["NORMAL_BEHAVIOR"] += diff

        print(f"Generating {self.total_rows:,} events across scenarios...")

        # ----------------------------------------------------
        # 1. SEQUENCED SCENARIOS (Attacks, Recon, Pivots)
        # ----------------------------------------------------
        # A. Reconnaissance Sequence (~12,000 events -> ~3,000 sequences of 4 events)
        recon_count = target_counts.get("RECONNAISSANCE", 12000)
        recon_tmpl = CORRELATED_SEQUENCE_TEMPLATES["Reconnaissance Sequence"]
        n_recon_seqs = recon_count // len(recon_tmpl)
        recon_times = generate_time_window(self.start_date, self.end_date, n_recon_seqs)

        for base_time in recon_times:
            seq_id = f"SEQ_REC_{self.sequence_counter:06d}"
            ses_id = f"SES_REC_{self.session_counter:06d}"
            self.sequence_counter += 1
            self.session_counter += 1

            # Could be attacker or curious user
            attacker_id = "compromised-contractor" if np.random.rand() > 0.3 else "dev-backend-user"
            source_ip = np.random.choice(IP_POOLS["external_suspicious"]) if attacker_id == "compromised-contractor" else np.random.choice(IP_POOLS["vpn"])
            reg = np.random.choice(AWS_REGIONS)

            for step_idx, ev_name in enumerate(recon_tmpl):
                t = base_time + datetime.timedelta(seconds=step_idx * np.random.randint(10, 45))
                events.append(self._create_event_dict(
                    dt=t,
                    event_name=ev_name,
                    identity_name=attacker_id,
                    source_ip=source_ip,
                    user_agent_key="suspicious_script" if attacker_id == "compromised-contractor" else "cli",
                    mfa_value="false" if attacker_id == "compromised-contractor" else "true",
                    session_id=ses_id,
                    behavior_sequence_id=seq_id,
                    behavior_label="SUSPICIOUS" if attacker_id != "compromised-contractor" else "ANOMALOUS",
                    attack_scenario="RECONNAISSANCE",
                    region=reg
                ))

        # B. Service Discovery Pattern (~8,000 events -> ~2,666 sequences of 3 events)
        sd_count = target_counts.get("SERVICE_DISCOVERY", 8000)
        sd_tmpl = CORRELATED_SEQUENCE_TEMPLATES["Service Discovery Pattern"]
        n_sd_seqs = sd_count // len(sd_tmpl)
        sd_times = generate_time_window(self.start_date, self.end_date, n_sd_seqs)

        for base_time in sd_times:
            seq_id = f"SEQ_SD_{self.sequence_counter:06d}"
            ses_id = f"SES_SD_{self.session_counter:06d}"
            self.sequence_counter += 1
            self.session_counter += 1

            ident = np.random.choice(["ops-infra-user", "dev-lead-user", "compromised-contractor"])
            src = np.random.choice(IP_POOLS["external_suspicious"] if ident == "compromised-contractor" else IP_POOLS["vpn"])
            label = "ANOMALOUS" if ident == "compromised-contractor" else "SUSPICIOUS"

            for step_idx, ev_name in enumerate(sd_tmpl):
                t = base_time + datetime.timedelta(seconds=step_idx * np.random.randint(5, 30))
                events.append(self._create_event_dict(
                    dt=t,
                    event_name=ev_name,
                    identity_name=ident,
                    source_ip=src,
                    user_agent_key="boto3",
                    mfa_value="true" if ident != "compromised-contractor" else "false",
                    session_id=ses_id,
                    behavior_sequence_id=seq_id,
                    behavior_label=label,
                    attack_scenario="SERVICE_DISCOVERY",
                    region=np.random.choice(AWS_REGIONS)
                ))

        # C. Sensitive IAM Activity (~6,000 events -> ~2,000 sequences of 3 events)
        siam_count = target_counts.get("SENSITIVE_IAM", 6000)
        siam_tmpl = CORRELATED_SEQUENCE_TEMPLATES["Sensitive IAM Activity"]
        n_siam_seqs = siam_count // len(siam_tmpl)
        siam_times = generate_time_window(self.start_date, self.end_date, n_siam_seqs)

        for base_time in siam_times:
            seq_id = f"SEQ_IAM_{self.sequence_counter:06d}"
            ses_id = f"SES_IAM_{self.session_counter:06d}"
            self.sequence_counter += 1
            self.session_counter += 1

            ident = np.random.choice(["dev-lead-user", "compromised-contractor", "sec-analyst-alice"])
            src = np.random.choice(IP_POOLS["external_suspicious"] if ident == "compromised-contractor" else IP_POOLS["corporate"])
            # Alice is a hard negative: she's a security analyst, so legitimate discovery!
            label = "NORMAL" if ident == "sec-analyst-alice" else ("ANOMALOUS" if ident == "compromised-contractor" else "SUSPICIOUS")

            for step_idx, ev_name in enumerate(siam_tmpl):
                t = base_time + datetime.timedelta(seconds=step_idx * np.random.randint(8, 25))
                events.append(self._create_event_dict(
                    dt=t,
                    event_name=ev_name,
                    identity_name=ident,
                    source_ip=src,
                    user_agent_key="cli",
                    mfa_value="true" if ident != "compromised-contractor" else "false",
                    session_id=ses_id,
                    behavior_sequence_id=seq_id,
                    behavior_label=label,
                    attack_scenario="SENSITIVE_IAM",
                    region="us-east-1"
                ))

        # D. Privilege Escalation Sequence (~4,000 events -> ~1,000 sequences of 4 events)
        pe_count = target_counts.get("PRIVILEGE_ESCALATION", 4000)
        pe_tmpl = CORRELATED_SEQUENCE_TEMPLATES["Privilege Escalation Sequence"]
        n_pe_seqs = pe_count // len(pe_tmpl)
        pe_times = generate_time_window(self.start_date, self.end_date, n_pe_seqs)

        for base_time in pe_times:
            seq_id = f"SEQ_PE_{self.sequence_counter:06d}"
            ses_id = f"SES_PE_{self.session_counter:06d}"
            self.sequence_counter += 1
            self.session_counter += 1

            ident = np.random.choice(["compromised-contractor", "dev-backend-user"])
            src = np.random.choice(IP_POOLS["external_suspicious"] if ident == "compromised-contractor" else IP_POOLS["vpn"])
            label = "ANOMALOUS"

            for step_idx, ev_name in enumerate(pe_tmpl):
                t = base_time + datetime.timedelta(seconds=step_idx * np.random.randint(12, 60))
                events.append(self._create_event_dict(
                    dt=t,
                    event_name=ev_name,
                    identity_name=ident,
                    source_ip=src,
                    user_agent_key="cli",
                    mfa_value="false" if ident == "compromised-contractor" else "true",
                    session_id=ses_id,
                    behavior_sequence_id=seq_id,
                    behavior_label=label,
                    attack_scenario="PRIVILEGE_ESCALATION",
                    region="us-east-1"
                ))

        # E. Compound Attack Chain (~2,000 events -> ~250 sequences of 8 events)
        cac_count = target_counts.get("COMPOUND_ATTACK_CHAIN", 2000)
        cac_tmpl = CORRELATED_SEQUENCE_TEMPLATES["Compound Attack Chain"]
        n_cac_seqs = cac_count // len(cac_tmpl)
        cac_times = generate_time_window(self.start_date, self.end_date, n_cac_seqs)

        for base_time in cac_times:
            seq_id = f"SEQ_CHAIN_{self.sequence_counter:06d}"
            ses_id = f"SES_CHAIN_{self.session_counter:06d}"
            self.sequence_counter += 1
            self.session_counter += 1

            ident = "compromised-contractor"
            src = np.random.choice(IP_POOLS["external_suspicious"])

            for step_idx, ev_name in enumerate(cac_tmpl):
                t = base_time + datetime.timedelta(seconds=step_idx * np.random.randint(15, 90))
                # Step 2 is an explicit failed sensitive call!
                err_code = "AccessDenied" if step_idx == 2 else ""
                err_msg = "User is not authorized to perform: iam:AttachRolePolicy" if step_idx == 2 else ""

                events.append(self._create_event_dict(
                    dt=t,
                    event_name=ev_name,
                    identity_name=ident,
                    source_ip=src,
                    user_agent_key="suspicious_script",
                    error_code=err_code,
                    error_message=err_msg,
                    mfa_value="false",
                    session_id=ses_id,
                    behavior_sequence_id=seq_id,
                    behavior_label="ANOMALOUS",
                    attack_scenario="COMPOUND_ATTACK_CHAIN",
                    region="us-east-1"
                ))

        # F. Failed Sensitive Operations (~3,000 events)
        fso_count = target_counts.get("FAILED_SENSITIVE_OPERATION", 3000)
        fso_times = generate_time_window(self.start_date, self.end_date, fso_count)
        failed_apis = ["AttachRolePolicy", "PutRolePolicy", "AssumeRole", "CreateAccessKey", "DeleteBucketPolicy"]

        for t in fso_times:
            ev = np.random.choice(failed_apis)
            ident = np.random.choice(["compromised-contractor", "dev-backend-user", "dev-frontend-user"])
            src = np.random.choice(IP_POOLS["external_suspicious"] if ident == "compromised-contractor" else IP_POOLS["vpn"])
            ses_id = f"SES_FSO_{self.session_counter:06d}"
            self.session_counter += 1

            events.append(self._create_event_dict(
                dt=t,
                event_name=ev,
                identity_name=ident,
                source_ip=src,
                user_agent_key="cli",
                error_code="AccessDenied",
                error_message=f"User is not authorized to perform {ev}",
                mfa_value="false" if ident == "compromised-contractor" else "true",
                session_id=ses_id,
                behavior_sequence_id="",
                behavior_label="ANOMALOUS" if ident == "compromised-contractor" else "SUSPICIOUS",
                attack_scenario="FAILED_SENSITIVE_OPERATION",
                region="us-east-1"
            ))

        # G. Credential Activity (~3,000 events)
        cred_count = target_counts.get("CREDENTIAL_ACTIVITY", 3000)
        cred_times = generate_time_window(self.start_date, self.end_date, cred_count)
        cred_apis = ["CreateAccessKey", "UpdateAccessKey", "DeleteAccessKey"]

        for t in cred_times:
            ev = np.random.choice(cred_apis)
            ident = np.random.choice(["compromised-contractor", "ops-infra-user", "dev-lead-user"])
            src = np.random.choice(IP_POOLS["external_suspicious"] if ident == "compromised-contractor" else IP_POOLS["corporate"])
            ses_id = f"SES_CRED_{self.session_counter:06d}"
            self.session_counter += 1

            events.append(self._create_event_dict(
                dt=t,
                event_name=ev,
                identity_name=ident,
                source_ip=src,
                user_agent_key="cli",
                mfa_value="false" if ident == "compromised-contractor" else "true",
                session_id=ses_id,
                behavior_sequence_id="",
                behavior_label="ANOMALOUS" if ident == "compromised-contractor" else "SUSPICIOUS",
                attack_scenario="CREDENTIAL_ACTIVITY",
                region="us-east-1"
            ))

        # ----------------------------------------------------
        # 2. HARD NEGATIVES & BASELINE ACTIVITY
        # ----------------------------------------------------
        # H. Service-to-Service Activity (~20,000 events - Hard Negative!)
        svc_count = target_counts.get("SERVICE_ACTIVITY", 20000)
        svc_times = generate_time_window(self.start_date, self.end_date, svc_count)
        svc_apis = ["DescribeAutoScalingGroups", "AssumeRole", "GetDatabases", "ListResources", "ListTables", "DescribeDBSubnetGroups"]

        for t in svc_times:
            ev = np.random.choice(svc_apis)
            src = np.random.choice(IP_POOLS["aws_service"])
            ses_id = f"SES_SVC_{self.session_counter:06d}"
            self.session_counter += 1

            events.append(self._create_event_dict(
                dt=t,
                event_name=ev,
                identity_name="AWSServiceRoleForResourceExplorer",
                source_ip=src,
                user_agent_key="service",
                mfa_value="unknown",
                session_id=ses_id,
                behavior_sequence_id="",
                behavior_label="NORMAL", # CRITICAL: Service activity is normal!
                attack_scenario="SERVICE_ACTIVITY",
                region="us-east-1"
            ))

        # I. Off-Hours Anomaly (~12,000 events - Mixture of Nightly Backups & Suspicious Off-Hours)
        off_count = target_counts.get("OFF_HOURS_ANOMALY", 12000)
        off_times = generate_time_window(self.start_date, self.end_date, off_count)

        for base_t in off_times:
            # Force hour to night (00:00 - 05:00)
            night_hour = np.random.choice([0, 1, 2, 3, 4, 5, 22, 23])
            t = base_t.replace(hour=night_hour, minute=np.random.randint(0, 59))
            ses_id = f"SES_OFF_{self.session_counter:06d}"
            self.session_counter += 1

            # 70% are legitimate scheduled automated backups (Hard Negative!)
            if np.random.rand() < 0.70:
                events.append(self._create_event_dict(
                    dt=t,
                    event_name=np.random.choice(["DescribeVolumes", "DescribeInstances", "DescribeTags"]),
                    identity_name="backup-agent-role",
                    source_ip=np.random.choice(IP_POOLS["cloud_vpc"]),
                    user_agent_key="boto3",
                    mfa_value="unknown",
                    session_id=ses_id,
                    behavior_sequence_id="",
                    behavior_label="NORMAL", # Scheduled off-hours is normal!
                    attack_scenario="OFF_HOURS_ANOMALY",
                    region="us-east-1"
                ))
            else:
                # 30% are suspicious off-hours interactive user activity
                ident = np.random.choice(["dev-backend-user", "compromised-contractor"])
                events.append(self._create_event_dict(
                    dt=t,
                    event_name=np.random.choice(["DescribeSecurityGroups", "ListBuckets", "GetRole"]),
                    identity_name=ident,
                    source_ip=np.random.choice(IP_POOLS["external_suspicious"] if ident == "compromised-contractor" else IP_POOLS["vpn"]),
                    user_agent_key="cli",
                    mfa_value="true" if ident != "compromised-contractor" else "false",
                    session_id=ses_id,
                    behavior_sequence_id="",
                    behavior_label="SUSPICIOUS",
                    attack_scenario="OFF_HOURS_ANOMALY",
                    region=np.random.choice(AWS_REGIONS)
                ))

        # J. MFA Anomaly (~8,000 events - Mixture of Legitimate Unknown MFA & Missing User MFA)
        mfa_count = target_counts.get("MFA_ANOMALY", 8000)
        mfa_times = generate_time_window(self.start_date, self.end_date, mfa_count)

        for t in mfa_times:
            ses_id = f"SES_MFA_{self.session_counter:06d}"
            self.session_counter += 1

            # 60% are legitimate CI/CD pipeline automation (MFA unknown - Hard Negative!)
            if np.random.rand() < 0.60:
                events.append(self._create_event_dict(
                    dt=t,
                    event_name=np.random.choice(["AssumeRole", "DescribeInstances", "DescribeAutoScalingGroups"]),
                    identity_name="ci-cd-deploy-role",
                    source_ip=np.random.choice(IP_POOLS["cloud_vpc"]),
                    user_agent_key="terraform",
                    mfa_value="unknown",
                    session_id=ses_id,
                    behavior_sequence_id="",
                    behavior_label="NORMAL",
                    attack_scenario="MFA_ANOMALY",
                    region="us-east-1"
                ))
            else:
                # 40% are human user failing to use MFA
                events.append(self._create_event_dict(
                    dt=t,
                    event_name=np.random.choice(["DescribeInstances", "ListBuckets", "GetCallerIdentity"]),
                    identity_name=np.random.choice(["dev-lead-user", "dev-backend-user"]),
                    source_ip=np.random.choice(IP_POOLS["vpn"]),
                    user_agent_key="cli",
                    mfa_value="false",
                    session_id=ses_id,
                    behavior_sequence_id="",
                    behavior_label="SUSPICIOUS",
                    attack_scenario="MFA_ANOMALY",
                    region=np.random.choice(AWS_REGIONS)
                ))

        # ----------------------------------------------------
        # 3. NORMAL DAY-TO-DAY BASELINE (Fill remainder to exactly total_rows)
        # ----------------------------------------------------
        remaining = self.total_rows - len(events)
        print(f"Generating remaining {remaining:,} standard normal baseline events...")

        normal_identities = [
            "dev-lead-user",
            "dev-backend-user",
            "dev-frontend-user",
            "ops-infra-user",
            "ops-platform-admin",
            "sec-analyst-alice",
            "sec-compliance-auditor",
            "ci-cd-deploy-role",
            "monitoring-agent-role",
        ]
        normal_times = generate_time_window(self.start_date, self.end_date, remaining)

        for t in normal_times:
            ident_name = np.random.choice(normal_identities)
            ident_info = IDENTITIES[ident_name]

            # Adjust hour to typical hours
            h_start, h_end = ident_info["normal_hours"]
            valid_hour = np.random.randint(h_start, h_end) if h_end > h_start else np.random.randint(8, 18)
            t_adj = t.replace(hour=valid_hour, minute=np.random.randint(0, 59))

            ev = np.random.choice(ident_info["typical_events"])
            src_pool_key = ident_info["source_pool"]
            src = np.random.choice(IP_POOLS.get(src_pool_key, IP_POOLS["corporate"]))

            mfa_p = ident_info["mfa_profile"]
            if mfa_p == "strictly_true":
                mfa_val = "true"
            elif mfa_p == "mostly_true":
                mfa_val = "true" if np.random.rand() > 0.02 else "false"
            else:
                mfa_val = "unknown"

            ses_id = f"SES_NORM_{self.session_counter:06d}"
            self.session_counter += 1

            events.append(self._create_event_dict(
                dt=t_adj,
                event_name=ev,
                identity_name=ident_name,
                source_ip=src,
                user_agent_key="console" if ident_info["user_type"] == "IAMUser" else "boto3",
                mfa_value=mfa_val,
                session_id=ses_id,
                behavior_sequence_id="",
                behavior_label="NORMAL",
                attack_scenario="NORMAL_BEHAVIOR",
                region=np.random.choice(AWS_REGIONS)
            ))

        print(f"Raw event synthesis complete: {len(events):,} events.")
        return events

    def build_and_save(self) -> pd.DataFrame:
        """
        Builds DataFrame, executes full behavioral feature engineering,
        and saves both CSV and JSONL outputs.
        """
        raw_events = self.generate_all_events()
        df = pd.DataFrame(raw_events)

        # Sort chronologically
        df["event_time_dt"] = pd.to_datetime(df["event_time"], utc=True)
        df = df.sort_values("event_time_dt").reset_index(drop=True)
        df = df.drop(columns=["event_time_dt"])

        # Compute all 17 features, rule scores, anomaly scores, composite risk scores
        df = compute_all_behavioral_features(df)

        # Generate explainable risk reasons & recommended action
        print("Generating explainable risk reasons and remediation actions...")
        # To make it super fast for 500k rows, we build reasons efficiently
        df["risk_reasons"] = df.apply(build_risk_reasons, axis=1)
        df["recommended_action"] = df["final_risk_level"].apply(get_recommended_action_text)

        # Verify row count
        assert len(df) == self.total_rows, f"Expected {self.total_rows} rows, got {len(df)}"

        # Save to CSV
        print(f"Writing CSV to {CLOUDTRAIL_CSV}...")
        df.to_csv(CLOUDTRAIL_CSV, index=False)
        print(f"CSV saved: {CLOUDTRAIL_CSV.stat().st_size / (1024 * 1024):.2f} MB")

        # Save to JSONL (CloudTrail format compatible with feature_extractor.py)
        print(f"Writing JSONL to {CLOUDTRAIL_JSONL}...")
        with open(CLOUDTRAIL_JSONL, "w", encoding="utf-8", buffering=1024 * 1024) as f:
            for row in df.to_dict(orient="records"):
                # Construct AWS CloudTrail internal JSON string
                ct_inner = {
                    "eventVersion": "1.11",
                    "userIdentity": {
                        "type": row["user_type"],
                        "principalId": row["principal_id"],
                        "arn": row["user_arn"],
                        "accountId": SYNTHETIC_ACCOUNT_ID,
                        "accessKeyId": row["access_key_id"],
                        "userName": row["user_name"],
                        "sessionContext": {
                            "attributes": {
                                "mfaAuthenticated": str(row["mfa_used"]).lower()
                            }
                        }
                    },
                    "eventTime": row["event_time"],
                    "eventSource": row["event_source"],
                    "eventName": row["event_name"],
                    "awsRegion": row["aws_region"],
                    "sourceIPAddress": row["source_ip"],
                    "userAgent": row["user_agent"],
                    "errorCode": row["error_code"] if row["error_code"] else None,
                    "errorMessage": row["error_message"] if row["error_message"] else None,
                    "readOnly": row["read_only"] == "True",
                    "recipientAccountId": SYNTHETIC_ACCOUNT_ID,
                }

                wrapper = {
                    "EventId": str(uuid.uuid4()),
                    "EventName": row["event_name"],
                    "ReadOnly": str(row["read_only"]),
                    "AccessKeyId": row["access_key_id"],
                    "EventTime": row["event_time"],
                    "EventSource": row["event_source"],
                    "Username": row["user_name"],
                    "CloudTrailEvent": json.dumps(ct_inner),
                    "session_id": row["session_id"],
                    "behavior_sequence_id": row["behavior_sequence_id"],
                    "behavior_label": row["behavior_label"],
                    "attack_scenario": row["attack_scenario"],
                    "final_risk_level": row["final_risk_level"],
                    "final_risk_score": row["final_risk_score"],
                }
                f.write(json.dumps(wrapper) + "\n")

        print(f"JSONL saved: {CLOUDTRAIL_JSONL.stat().st_size / (1024 * 1024):.2f} MB")
        return df


def main():
    generator = CloudTrailDatasetGenerator(total_rows=DEFAULT_ROW_COUNT, seed=RANDOM_SEED)
    df = generator.build_and_save()
    print("CloudTrail dataset generation completed successfully.")


if __name__ == "__main__":
    main()
