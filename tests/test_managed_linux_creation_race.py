# SPDX-License-Identifier: Apache-2.0
"""Pure daemon-completion race regressions; no Docker or process execution."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from scripts.managed_release_linux import controller as C


class CreationRaceTests(unittest.TestCase):
    def ledger(self):
        host = SimpleNamespace(named_inventory=Mock(return_value={}), inspect=Mock(),
                               docker=Mock(side_effect=C.Refused("command-deadline")))
        ledger = C.CreationLedger(host, "a" * 32, wall=lambda: 100)
        pending = ledger.reserve("container", "maskura-managed-case-" + "b" * 32,
                                 "b" * 32, "sha256:" + "c" * 64, 200)
        return host, ledger, pending

    def test_timeout_and_repeated_empty_inventory_never_prove_absence(self):
        host, ledger, pending = self.ledger()
        with self.assertRaises(C.Refused):
            ledger.create(pending, ["create"], 200, lambda: 210)
        self.assertTrue(pending.attempted)
        self.assertFalse(pending.completed)
        for _ in range(3):
            with self.assertRaisesRegex(C.Refused, "^creation-request-unresolved$"):
                ledger.reconcile(pending, 210)
            self.assertFalse(pending.absent)
        self.assertGreater(host.named_inventory.call_count, 3)

    def test_late_visible_create_is_owned_but_does_not_finish_original_request(self):
        host, ledger, pending = self.ledger()
        with self.assertRaises(C.Refused):
            ledger.create(pending, ["create"], 200, lambda: 210)
        identity = "d" * 64
        host.named_inventory.return_value = {pending.name: identity}
        host.inspect.return_value = dict(Id=identity, Name="/" + pending.name,
                                         Created="1970-01-01T00:01:40Z", Image=pending.image,
                                         Config=dict(Labels={C.LABEL: "a" * 32,
                                                             C.LABEL + ".nonce": pending.nonce}))
        owned = ledger.reconcile(pending, 210)
        self.assertEqual(owned.identity, identity)
        self.assertFalse(pending.completed)
        warden = C.Warden.__new__(C.Warden)
        warden.creations, warden.end, warden.remove = ledger, Mock(return_value=210), Mock()
        with self.assertRaisesRegex(C.Refused, "^pending-creation-cleanup-unproved$"):
            warden.cleanup_pending()
        warden.remove.assert_called_once_with(owned)

    def test_removed_resource_does_not_clear_a_timed_out_request(self):
        _host, ledger, pending = self.ledger()
        pending.attempted, pending.removed = True, True
        warden = C.Warden.__new__(C.Warden)
        warden.creations = ledger
        with self.assertRaisesRegex(C.Refused, "^pending-creation-cleanup-unproved$"):
            warden.cleanup_pending()

    def test_reservation_never_dispatched_can_be_proved_absent(self):
        _host, ledger, pending = self.ledger()
        self.assertIsNone(ledger.reconcile(pending, 200))
        self.assertTrue(pending.absent)


if __name__ == "__main__":
    unittest.main()
