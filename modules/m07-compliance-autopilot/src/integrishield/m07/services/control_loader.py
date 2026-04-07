"""Control loader — reads YAML control definition files at startup."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from integrishield.m07.models import ControlDefinition, Framework

logger = logging.getLogger(__name__)


class ControlLoader:
    """Loads and indexes control definitions from YAML files."""

    def __init__(self, config_path: str) -> None:
        self._path = Path(config_path)
        self._controls: dict[str, ControlDefinition] = {}

    def load(self) -> int:
        """Load all YAML files from config_path. Returns number of controls loaded."""
        self._controls.clear()

        framework_files = {
            Framework.SOX: "sox.yaml",
            Framework.SOC2: "soc2.yaml",
            Framework.ISO27001: "iso27001.yaml",
            Framework.GDPR: "gdpr.yaml",
        }

        for framework, filename in framework_files.items():
            filepath = self._path / filename
            if not filepath.exists():
                logger.warning("Control file not found: %s", filepath)
                continue
            try:
                data = yaml.safe_load(filepath.read_text())
                for ctrl in data.get("controls", []):
                    definition = ControlDefinition(
                        control_id=ctrl["control_id"],
                        framework=framework,
                        title=ctrl.get("title", ""),
                        description=ctrl.get("description", ""),
                        evidence_streams=ctrl.get("evidence_streams", []),
                        violation_streams=ctrl.get("violation_streams", []),
                        remediation_guidance=ctrl.get("remediation_guidance", ""),
                    )
                    self._controls[definition.control_id] = definition
                logger.info("Loaded %d controls from %s", len(data.get("controls", [])), filename)
            except Exception:
                logger.exception("Failed to load control file: %s", filepath)

        logger.info("Total controls loaded: %d", len(self._controls))
        return len(self._controls)

    def get_all(self) -> dict[str, ControlDefinition]:
        return dict(self._controls)

    def get_control(self, control_id: str) -> ControlDefinition | None:
        return self._controls.get(control_id)

    def get_for_framework(self, framework: Framework) -> list[ControlDefinition]:
        return [c for c in self._controls.values() if c.framework == framework]

    def get_for_stream(self, stream_name: str) -> list[ControlDefinition]:
        """Return all controls that list this stream as an evidence source."""
        return [c for c in self._controls.values() if stream_name in c.evidence_streams]

    def is_violation_stream(self, control_id: str, stream_name: str) -> bool:
        ctrl = self._controls.get(control_id)
        if ctrl is None:
            return False
        return stream_name in ctrl.violation_streams

    @property
    def count(self) -> int:
        return len(self._controls)
