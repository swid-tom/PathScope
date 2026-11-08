"""Safe persistence helpers for the YAML configuration file."""
from __future__ import annotations

import errno
import logging
import os
import tempfile

import yaml

log = logging.getLogger(__name__)


def update_config_file(path: str, updates: dict) -> None:
    with open(path, "r", encoding="utf-8") as config_file:
        raw = yaml.safe_load(config_file) or {}
    raw.update(updates)
    _write_config_atomically(path, raw)


def update_config_section(path: str, section: str, updates: dict) -> None:
    with open(path, "r", encoding="utf-8") as config_file:
        raw = yaml.safe_load(config_file) or {}
    section_data = raw.get(section) or {}
    section_data.update(updates)
    raw[section] = section_data
    _write_config_atomically(path, raw)


def _write_config_atomically(path: str, raw: dict) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    file_descriptor, temporary_path = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.", suffix=".tmp", dir=directory
    )
    try:
        os.chmod(temporary_path, os.stat(path).st_mode & 0o777)
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as config_file:
            yaml.safe_dump(raw, config_file, sort_keys=False)
            config_file.flush()
            os.fsync(config_file.fileno())
        try:
            os.replace(temporary_path, path)
        except OSError as exc:
            if exc.errno != errno.EBUSY:
                raise
            log.warning(
                "config file %s is a bind mount; updating it in place instead of atomically",
                path,
            )
            with open(temporary_path, "r", encoding="utf-8") as staged_file:
                contents = staged_file.read()
            with open(path, "w", encoding="utf-8") as config_file:
                config_file.write(contents)
                config_file.flush()
                os.fsync(config_file.fileno())
            os.unlink(temporary_path)
    except BaseException:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise
