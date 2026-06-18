"""Tests for config.py."""

import json
import os
import tempfile

import pytest

import config as cfg


class TestDefaults:
    def test_returns_dict(self):
        c = cfg.load()
        assert isinstance(c, dict)

    def test_has_required_keys(self):
        c = cfg.load()
        for key in ("mode", "threads", "output", "modules", "dns"):
            assert key in c, f"Missing key: {key}"

    def test_default_mode(self):
        assert cfg.load()["mode"] == "normal"

    def test_default_thread_counts(self):
        c = cfg.load()
        assert c["threads"]["dns"]   == 15
        assert c["threads"]["ports"] == 50

    def test_default_formats(self):
        assert "json" in cfg.load()["output"]["formats"]
        assert "markdown" in cfg.load()["output"]["formats"]


class TestJsonLoad:
    def test_loads_json_file(self, tmp_path):
        p = tmp_path / "bhp.json"
        p.write_text(json.dumps({"mode": "aggressive"}))
        c = cfg.load(str(p))
        assert c["mode"] == "aggressive"

    def test_merges_over_defaults(self, tmp_path):
        p = tmp_path / "bhp.json"
        p.write_text(json.dumps({"threads": {"dns": 30}}))
        c = cfg.load(str(p))
        assert c["threads"]["dns"]   == 30
        assert c["threads"]["ports"] == 50    # default preserved

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            cfg.load(str(tmp_path / "nonexistent.json"))

    def test_nested_deep_merge(self, tmp_path):
        p = tmp_path / "bhp.json"
        p.write_text(json.dumps({"output": {"formats": ["json", "html"]}}))
        c = cfg.load(str(p))
        assert "html" in c["output"]["formats"]
        assert c["output"]["dir"] == "."      # default preserved

    def test_does_not_mutate_defaults(self, tmp_path):
        original_mode = cfg.DEFAULTS["mode"]
        p = tmp_path / "bhp.json"
        p.write_text(json.dumps({"mode": "aggressive"}))
        cfg.load(str(p))
        assert cfg.DEFAULTS["mode"] == original_mode


class TestDeepMerge:
    def test_scalar_override(self):
        base = {"a": 1, "b": 2}
        cfg._deep_merge(base, {"a": 99})
        assert base == {"a": 99, "b": 2}

    def test_nested_dict_merge(self):
        base = {"x": {"y": 1, "z": 2}}
        cfg._deep_merge(base, {"x": {"y": 99}})
        assert base == {"x": {"y": 99, "z": 2}}

    def test_adds_new_keys(self):
        base = {"a": 1}
        cfg._deep_merge(base, {"b": 2})
        assert base["b"] == 2

    def test_list_replaced_not_merged(self):
        base = {"formats": ["json"]}
        cfg._deep_merge(base, {"formats": ["html"]})
        assert base["formats"] == ["html"]


class TestDeepCopy:
    def test_independence_from_original(self):
        original = {"a": {"b": [1, 2, 3]}}
        copy = cfg._deep_copy(original)
        copy["a"]["b"].append(99)
        assert original["a"]["b"] == [1, 2, 3]
