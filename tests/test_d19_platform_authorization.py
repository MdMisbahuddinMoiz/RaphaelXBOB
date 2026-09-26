"""Platform-authorization tests for the generalized target profile layer.

Covers the invariant that generalizing the platform registry did NOT widen the
permissive surface:

  * HTB remains fully supported with its original defaults (no regression).
  * Non-HTB platforms are accepted ONLY when the operator explicitly declares
    an authorized, isolated, in-scope lab target.
  * Non-HTB platforms can never silently inherit a non-isolated default.
  * No individual target/image/challenge name is hard-coded in the product
    layer, so the registry stays generic.
"""
import inspect
import unittest

from raphael_ibm_bob import target_profile as tp
from raphael_ibm_bob.target_profile import (
    ALLOWED_PLATFORMS,
    ISOLATED_ENVIRONMENTS,
    PLATFORM_SPECS,
    PlatformSpec,
    TargetProfile,
    TargetProfileError,
    build_target_profile,
)

LAB_SCOPE = "192.168.200.0/24"
LAB_HOST = "192.168.200.10"
NON_HTB = tuple(s.name for s in PLATFORM_SPECS if s.requires_isolated_environment)


def _lab_target(**overrides):
    kwargs = dict(
        mission_id="M-lab",
        locator=LAB_HOST,
        allowed_ports=[80],
        allowed_protocols=["http"],
        scope=LAB_SCOPE,
        authorization_ref="operator-declared-lab",
        environment=ISOLATED_ENVIRONMENTS[0],
    )
    kwargs.update(overrides)
    return build_target_profile(**kwargs)


class HtbUnchanged(unittest.TestCase):
    def test_htb_still_default_platform(self):
        p = build_target_profile(
            mission_id="M1", locator="10.129.48.95", allowed_ports=[80, 443],
            allowed_protocols=["http", "https"], authorization_ref="auth-1")
        self.assertEqual(p.platform, "htb")

    def test_htb_environment_default_preserved(self):
        p = build_target_profile(
            mission_id="M1", locator="10.129.48.95", allowed_ports=[80],
            allowed_protocols=["http"], authorization_ref="auth-1")
        self.assertEqual(p.environment, "htb")

    def test_htb_needs_no_isolation_attestation(self):
        p = _lab_target(platform="htb", environment=None)
        self.assertEqual(p.environment, "htb")

    def test_htb_allow_list_membership(self):
        self.assertIn("htb", ALLOWED_PLATFORMS)

    def test_htb_allows_unchanged(self):
        p = build_target_profile(
            mission_id="M1", locator="10.129.48.95", allowed_ports=[80],
            allowed_protocols=["http"], authorization_ref="auth-1")
        self.assertTrue(p.allows(host="10.129.48.95", port=80, protocol="http"))
        self.assertFalse(p.allows(host="10.129.48.96", port=80, protocol="http"))
        self.assertFalse(p.allows(host="10.129.48.95", port=8080,
                                  protocol="http"))


class NonHtbRequiresExplicitIsolation(unittest.TestCase):
    def test_non_htb_registry_is_populated(self):
        self.assertTrue(NON_HTB, "expected at least one isolation-gated platform")

    def test_non_htb_rejected_without_environment(self):
        for platform in NON_HTB:
            with self.subTest(platform=platform):
                with self.assertRaises(TargetProfileError) as ctx:
                    _lab_target(platform=platform, environment=None)
                self.assertIn("requires an explicit isolated", str(ctx.exception))

    def test_non_htb_rejected_with_non_isolated_environment(self):
        for platform in NON_HTB:
            with self.subTest(platform=platform):
                with self.assertRaises(TargetProfileError) as ctx:
                    _lab_target(platform=platform, environment="htb")
                self.assertIn("must be authorized in an isolated",
                              str(ctx.exception))

    def test_non_htb_accepted_when_explicitly_isolated_and_scoped(self):
        for platform in NON_HTB:
            with self.subTest(platform=platform):
                p = _lab_target(platform=platform)
                self.assertEqual(p.platform, platform)
                self.assertIn(p.environment, ISOLATED_ENVIRONMENTS)
                self.assertTrue(p.allows(host=LAB_HOST, port=80,
                                         protocol="http"))

    def test_non_htb_still_requires_authorization_ref(self):
        for platform in NON_HTB:
            with self.subTest(platform=platform):
                with self.assertRaises(TargetProfileError):
                    _lab_target(platform=platform, authorization_ref="")

    def test_non_htb_still_enforces_scope_containment(self):
        for platform in NON_HTB:
            with self.subTest(platform=platform):
                with self.assertRaises(TargetProfileError):
                    _lab_target(platform=platform, locator="10.66.0.9")

    def test_non_htb_refined_preserves_platform_and_isolation(self):
        for platform in NON_HTB:
            with self.subTest(platform=platform):
                disc = build_target_profile(
                    mission_id="M-lab", locator=LAB_HOST, allowed_ports=[],
                    allowed_protocols=[], scope=LAB_SCOPE,
                    authorization_ref="operator-declared-lab",
                    platform=platform, environment=ISOLATED_ENVIRONMENTS[0],
                    stage=tp.TARGET_STAGE_DISCOVERY)
                self.assertTrue(disc.is_discovery_only)
                auth = disc.refined(allowed_ports=[80], allowed_protocols=["http"])
                self.assertEqual(auth.platform, platform)
                self.assertIn(auth.environment, ISOLATED_ENVIRONMENTS)


class DirectConstructionCannotBypassIsolation(unittest.TestCase):
    def test_direct_construction_rejects_non_isolated_non_htb(self):
        for platform in NON_HTB:
            with self.subTest(platform=platform):
                with self.assertRaises(TargetProfileError):
                    TargetProfile(
                        target_id="TP-manual", mission_id="M-lab",
                        platform=platform, locator=LAB_HOST,
                        allowed_ports=(80,), allowed_protocols=("http",),
                        scope=LAB_SCOPE, authorization_ref="a",
                        environment="htb")

    def test_unknown_platform_rejected_everywhere(self):
        with self.assertRaises(TargetProfileError):
            build_target_profile(mission_id="M1", locator="10.0.0.1",
                                 allowed_ports=[80], allowed_protocols=["http"],
                                 authorization_ref="a", platform="bogus")
        with self.assertRaises(TargetProfileError):
            TargetProfile(target_id="TP-x", mission_id="M1", platform="bogus",
                          locator="10.0.0.1", allowed_ports=(80,),
                          allowed_protocols=("http",), scope="10.0.0.1",
                          authorization_ref="a")


class RegistryStaysGeneric(unittest.TestCase):
    FORBIDDEN = ("kioptrix", "kioptix", "metasploitable", "vulnhub_box")

    def test_no_individual_target_named_in_product_layer(self):
        source = inspect.getsource(tp).lower()
        for needle in self.FORBIDDEN:
            with self.subTest(needle=needle):
                # 'vulnhub' as a platform family is fine; a specific target is not.
                if needle == "vulnhub_box":
                    continue
                self.assertNotIn(needle, source)

    def test_every_registered_platform_has_a_spec(self):
        for spec in PLATFORM_SPECS:
            self.assertIsInstance(spec, PlatformSpec)
            self.assertIn(spec.name, ALLOWED_PLATFORMS)

    def test_only_htb_may_skip_isolation(self):
        non_isolated = [s.name for s in PLATFORM_SPECS
                        if not s.requires_isolated_environment]
        self.assertEqual(non_isolated, ["htb"])


if __name__ == "__main__":
    unittest.main()
