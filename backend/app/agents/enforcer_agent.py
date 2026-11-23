import time
import os
import uuid
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.models import BlocklistEntry, ActionLog, QuarantinedFile
from backend.app.utils.security import compute_sha256

class EnforcerAgent:
    """
    Agent 4: Enforcer Agent
    Purpose: Executes safe, application-managed containment and remediation actions.
             Strictly non-invasive (never modifies host firewall, OS registry, or external network).
    """
    AGENT_NAME = "Enforcer Agent"
    ROLE = "Security Response Execution"

    @classmethod
    async def process(
        cls,
        task_id: str,
        file_agent_output: Dict[str, Any],
        policy_agent_output: Dict[str, Any],
        db: Session,
        raw_input: Optional[Dict[str, Any]] = None,
        private_payload: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        start_time = time.time()
        file_data = file_agent_output.get("data", {})
        policy_data = policy_agent_output.get("data", {})
        decision = policy_data.get("decision", "ALLOW")

        actions_taken = []
        quarantined_files_info = []
        neutralized_urls = []

        try:
            # 1. URL Blocking & Neutralization
            extracted_urls = file_data.get("extracted_urls", [])
            for url in extracted_urls:
                # Wrap with application safety interceptor
                safe_wrapped = f"/safe-redirect?target={url}&blocked=true"
                neutralized_urls.append({
                    "original_url": url,
                    "safe_url": safe_wrapped,
                    "neutralized": decision in ("BLOCK_QUARANTINE", "WARN_REVIEW")
                })

                # If Critical, add to Internal DB Blocklist
                if decision == "BLOCK_QUARANTINE":
                    existing = db.query(BlocklistEntry).filter(BlocklistEntry.value == url).first()
                    if not existing:
                        entry = BlocklistEntry(
                            entry_type="URL",
                            value=url,
                            reason="Automated quarantine by PhishSentinel",
                            severity="CRITICAL",
                            added_by=cls.AGENT_NAME
                        )
                        db.add(entry)
                        actions_taken.append(f"Enforced blocklist entry for malicious URL: '{url[:50]}'")

            # 2. File Quarantine Execution
            attachments = file_data.get("attachments_metadata", [])
            if decision == "BLOCK_QUARANTINE" and attachments:
                for att in attachments:
                    fname = att.get("filename", "unnamed_payload")
                    raw_bytes = att.get("raw_bytes")

                    # File Agent intentionally omits raw bytes from its output so
                    # agent data stays JSON-serializable. For QR uploads the
                    # original image is still available in the non-persisted
                    # raw_input channel and is what gets quarantined.
                    if not raw_bytes and file_data.get("scan_type") == "QR" and raw_input:
                        raw_bytes = raw_input.get("image_bytes")

                    # Email attachment bytes travel through the private,
                    # non-persisted channel so the original payload is stored.
                    if not raw_bytes and private_payload:
                        raw_bytes = private_payload.get("attachment_bytes", {}).get(fname)

                    # If raw bytes exist, quarantine to app-managed storage
                    stored_name = f"quarantine_{uuid.uuid4().hex[:12]}_{fname}"
                    storage_path = settings.QUARANTINE_DIR / stored_name
                    
                    if raw_bytes:
                        with open(storage_path, "wb") as f:
                            f.write(raw_bytes)
                        sha256 = compute_sha256(raw_bytes)
                        fsize = len(raw_bytes)
                    else:
                        # Synthetic/Simulated quarantine entry for inspection
                        dummy_content = f"Simulated quarantine placeholder for {fname}".encode()
                        with open(storage_path, "wb") as f:
                            f.write(dummy_content)
                        sha256 = compute_sha256(dummy_content)
                        fsize = att.get("size", len(dummy_content))

                    q_file = QuarantinedFile(
                        original_filename=fname,
                        stored_filename=stored_name,
                        file_path=str(storage_path),
                        file_size=fsize,
                        file_hash=sha256,
                        quarantine_reason=f"Policy directive: {policy_data.get('action_label')}",
                        status="QUARANTINED"
                    )
                    db.add(q_file)
                    db.flush()

                    quarantined_files_info.append({
                        "quarantine_id": q_file.id,
                        "original_filename": fname,
                        "stored_filename": stored_name,
                        "file_hash": sha256
                    })
                    actions_taken.append(f"Quarantined attachment '{fname}' to secure storage ({sha256[:16]}...)")

            # 3. Commit DB changes
            db.commit()

        except Exception as e:
            db.rollback()
            actions_taken.append(f"Enforcement error: {str(e)}")

        execution_time = time.time() - start_time
        summary = (
            f"Executed {len(actions_taken)} security actions under {decision} policy. "
            f"Neutralized {len(neutralized_urls)} links, quarantined {len(quarantined_files_info)} files."
        )

        return {
            "agent_name": cls.AGENT_NAME,
            "role": cls.ROLE,
            "task_id": task_id,
            "status": "SUCCESS",
            "execution_time_ms": round(execution_time * 1000, 2),
            "summary": summary,
            "data": {
                "decision_executed": decision,
                "actions_taken": actions_taken,
                "quarantined_files": quarantined_files_info,
                "neutralized_urls": neutralized_urls
            }
        }
