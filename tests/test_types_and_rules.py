"""
test_types_and_rules.py
Unit tests for dpi/types.py (sni_to_app_type mapping) and
dpi/rule_manager.py (IP / app / domain blocking logic).
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dpi.types import sni_to_app_type, AppType
from dpi.rule_manager import RuleManager


class TestSniToAppType:
    def test_youtube(self):
        assert sni_to_app_type("www.youtube.com") == AppType.YOUTUBE

    def test_facebook(self):
        assert sni_to_app_type("m.facebook.com") == AppType.FACEBOOK

    def test_github(self):
        assert sni_to_app_type("api.github.com") == AppType.GITHUB

    def test_unknown_domain(self):
        assert sni_to_app_type("some-random-site.example") == AppType.UNKNOWN

    def test_case_insensitive(self):
        assert sni_to_app_type("WWW.YOUTUBE.COM") == AppType.YOUTUBE

    def test_youtube_takes_priority_over_google(self):
        # "youtube" should match before the generic "google" pattern
        assert sni_to_app_type("i.ytimg.com") == AppType.UNKNOWN
        assert sni_to_app_type("googlevideo.com") == AppType.YOUTUBE


class TestRuleManager:
    def test_blocks_by_ip(self):
        rules = RuleManager()
        rules.block_ip("192.168.1.50")
        assert rules.is_blocked("192.168.1.50", AppType.UNKNOWN, None) is True
        assert rules.is_blocked("192.168.1.51", AppType.UNKNOWN, None) is False

    def test_blocks_by_app(self):
        rules = RuleManager()
        rules.block_app(AppType.YOUTUBE)
        assert rules.is_blocked("1.2.3.4", AppType.YOUTUBE, None) is True
        assert rules.is_blocked("1.2.3.4", AppType.GITHUB, None) is False

    def test_blocks_by_domain_substring(self):
        rules = RuleManager()
        rules.block_domain("facebook")
        assert rules.is_blocked("1.2.3.4", AppType.UNKNOWN, "www.facebook.com") is True
        assert rules.is_blocked("1.2.3.4", AppType.UNKNOWN, "www.github.com") is False

    def test_domain_match_is_case_insensitive(self):
        rules = RuleManager()
        rules.block_domain("TikTok")
        assert rules.is_blocked("1.2.3.4", AppType.UNKNOWN, "www.tiktok.com") is True

    def test_no_rules_means_nothing_blocked(self):
        rules = RuleManager()
        assert rules.is_blocked("1.2.3.4", AppType.YOUTUBE, "www.youtube.com") is False

    def test_none_sni_does_not_crash_domain_check(self):
        rules = RuleManager()
        rules.block_domain("facebook")
        assert rules.is_blocked("1.2.3.4", AppType.UNKNOWN, None) is False
