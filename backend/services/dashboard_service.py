"""Dashboard service: one coherent aggregate response, no N+1.

Ownership always applies: the user's projects (admins see all). A
handful of COUNT/GROUP BY queries; no new indexes (small tables;
documented evidence-gated future addition if dashboard latency ever
requires it).
"""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.db.models import Asset, Finding, Project, Scan, User
from backend.services.scan_service import findings_counts_by_scan, scan_out

SCAN_STATUSES = (
    "queued",
    "initializing",
    "running",
    "cancelling",
    "completed",
    "failed",
    "cancelled",
)
SEVERITIES = ("critical", "high", "medium", "low", "info")

DEFAULT_RECENT_LIMIT = 6


def dashboard_data(session: Session, *, user: User, recent_limit: int = DEFAULT_RECENT_LIMIT) -> dict:
    """Aggregate dashboard data visible to the user."""
    project_filter = None if user.role == "admin" else Project.owner_id == user.id

    def _base(query):
        return query.where(project_filter) if project_filter is not None else query

    total_projects = (
        session.scalar(_base(select(func.count()).select_from(Project))) or 0
    )

    scan_base = _base(select(Scan).join(Project, Scan.project_id == Project.id))
    total_scans = (
        session.scalar(select(func.count()).select_from(scan_base.subquery())) or 0
    )
    # Group by the SUBQUERY's column, not the entity attribute: grouping by
    # Scan.status would implicitly re-add the scans table to the FROM clause
    # (cartesian product) and multiply every count.
    scan_sub = scan_base.subquery()
    status_rows = session.execute(
        select(scan_sub.c.status, func.count())
        .select_from(scan_sub)
        .group_by(scan_sub.c.status)
    ).all()
    scans_by_status = {s: 0 for s in SCAN_STATUSES}
    for status, count in status_rows:
        scans_by_status[status] = int(count)
    running_scans = scans_by_status.get("running", 0)

    finding_base = _base(select(Finding).join(Project, Finding.project_id == Project.id))
    total_findings = (
        session.scalar(select(func.count()).select_from(finding_base.subquery())) or 0
    )
    finding_sub = finding_base.subquery()
    severity_rows = session.execute(
        select(finding_sub.c.scanner_severity, func.count())
        .select_from(finding_sub)
        .group_by(finding_sub.c.scanner_severity)
    ).all()
    findings_by_severity = {s: 0 for s in SEVERITIES}
    for severity, count in severity_rows:
        findings_by_severity[severity] = int(count)

    asset_base = _base(select(Asset).join(Project, Asset.project_id == Project.id))
    total_assets = (
        session.scalar(select(func.count()).select_from(asset_base.subquery())) or 0
    )

    recent = list(
        session.scalars(
            _base(select(Scan).join(Project, Scan.project_id == Project.id))
            .order_by(Scan.created_at.desc())
            .limit(recent_limit)
        ).all()
    )
    counts = findings_counts_by_scan(session, [s.id for s in recent])
    recent_scans = [scan_out(s, counts.get(s.id)) for s in recent]

    return {
        "total_projects": total_projects,
        "total_scans": total_scans,
        "running_scans": running_scans,
        "scans_by_status": scans_by_status,
        "total_findings": total_findings,
        "findings_by_severity": findings_by_severity,
        "total_assets": total_assets,
        "recent_scans": recent_scans,
    }
