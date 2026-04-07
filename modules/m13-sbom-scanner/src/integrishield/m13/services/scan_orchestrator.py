"""Scan orchestrator — coordinates async ABAP code scanning."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import uuid
from datetime import datetime, timezone

import redis as redis_lib

from integrishield.m13.config import settings
from integrishield.m13.models import (
    SbomScanEvent,
    ScanFinding,
    ScanResult,
    ScanStatus,
    ScanSubmitRequest,
    ScanSubmitResponse,
    VulnSeverity,
)
from integrishield.m13.services import (
    cyclonedx_builder,
)
from integrishield.m13.services.scan_store import ScanStore
from integrishield.m13.services.scanners import (
    credential_scanner,
    dependency_extractor,
    rfc_scanner,
    sql_scanner,
)

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Coordinates scan submission, execution, and result storage."""

    def __init__(self, store: ScanStore) -> None:
        self._store = store
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_scans)
        self._redis: redis_lib.Redis | None = None
        self._extra_rfc_blocklist: set[str] = set(
            settings.insecure_rfc_blocklist.upper().split(",")
        )

    def connect_redis(self) -> None:
        try:
            self._redis = redis_lib.Redis.from_url(settings.redis_url, decode_responses=True)
            self._redis.ping()
            logger.info("m13 Redis connected at %s", settings.redis_url)
        except Exception as exc:
            logger.warning("m13 Redis connection failed: %s — events will not be published", exc)
            self._redis = None

    def submit(self, req: ScanSubmitRequest) -> ScanSubmitResponse:
        """Register a scan and schedule it asynchronously."""
        if len(req.content.encode()) > settings.max_scan_size_bytes:
            raise ValueError(
                f"Content size exceeds limit of {settings.max_scan_size_bytes} bytes"
            )

        scan_id = str(uuid.uuid4())
        now = datetime.now(tz=timezone.utc)
        result = ScanResult(
            scan_id=scan_id,
            filename=req.filename,
            status=ScanStatus.PENDING,
            submitted_at=now,
            tenant_id=req.tenant_id,
        )
        self._store.put(result)

        # Decode content
        if req.encoding == "base64":
            try:
                code = base64.b64decode(req.content).decode("utf-8", errors="replace")
            except Exception:
                code = req.content
        else:
            code = req.content

        asyncio.create_task(self._run_scan(scan_id, code, req.filename, req.tenant_id))

        return ScanSubmitResponse(
            scan_id=scan_id,
            status=ScanStatus.PENDING,
            submitted_at=now,
            poll_url=f"/api/v1/sbom/scans/{scan_id}",
        )

    async def _run_scan(
        self, scan_id: str, code: str, filename: str, tenant_id: str
    ) -> None:
        async with self._semaphore:
            result = self._store.get(scan_id)
            if result is None:
                return

            result.status = ScanStatus.RUNNING
            self._store.put(result)

            findings: list[ScanFinding] = []
            try:
                # Run all scanners (CPU-bound but small enough for POC inline)
                findings += credential_scanner.scan(scan_id, code)
                findings += sql_scanner.scan(scan_id, code)
                findings += rfc_scanner.scan(scan_id, code, self._extra_rfc_blocklist)
                components, dep_findings = dependency_extractor.extract(scan_id, code)
                findings += dep_findings

                # Count by severity
                counts: dict[str, int] = {s.value: 0 for s in VulnSeverity}
                for f in findings:
                    counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

                completed_at = datetime.now(tz=timezone.utc)
                result.findings = findings
                result.components = components
                result.finding_counts = counts
                result.status = ScanStatus.COMPLETE
                result.completed_at = completed_at
                self._store.put(result)

                self._publish_event(result)
                logger.info(
                    "Scan %s complete: %d findings (%d critical)",
                    scan_id,
                    len(findings),
                    counts.get("critical", 0),
                )

            except Exception:
                logger.exception("Scan %s failed", scan_id)
                result.status = ScanStatus.FAILED
                result.completed_at = datetime.now(tz=timezone.utc)
                self._store.put(result)
                self._publish_event(result)

    def _publish_event(self, result: ScanResult) -> None:
        if self._redis is None:
            return
        try:
            event = SbomScanEvent(
                event_id=str(uuid.uuid4()),
                scan_id=result.scan_id,
                filename=result.filename,
                tenant_id=result.tenant_id,
                total_findings=len(result.findings),
                critical_findings=result.finding_counts.get("critical", 0),
                status=result.status,
            )
            self._redis.xadd(
                settings.publish_stream,
                {"data": event.model_dump_json()},
            )
        except Exception:
            logger.exception("Failed to publish scan event for %s", result.scan_id)

    def build_sbom(self, scan_id: str) -> dict | None:
        result = self._store.get(scan_id)
        if result is None or result.status != ScanStatus.COMPLETE:
            return None
        return cyclonedx_builder.build(result)

    def redis_ok(self) -> bool:
        if self._redis is None:
            return False
        try:
            self._redis.ping()
            return True
        except Exception:
            return False
