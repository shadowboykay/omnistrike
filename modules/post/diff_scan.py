"""diff_scan — compare two scans"""
from core.diff import diff_latest_two, diff_scans
from pathlib import Path


class DiffScan:
    def run(self, session, logger):
        # если указаны два файла в --extra old=... new=...
        old = new = None
        for x in session.extra:
            if x.startswith("old="):
                old = x.split("=", 1)[1]
            elif x.startswith("new="):
                new = x.split("=", 1)[1]

        if old and new:
            result = diff_scans(old, new)
        else:
            result = diff_latest_two()

        if result:
            for f in result["new"]:
                logger.finding("diff_new", f.get("severity", "info"),
                               f.get("detail", ""))
        return result or {}
