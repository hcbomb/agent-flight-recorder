from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_flight_recorder.models import Action
from agent_flight_recorder.policy import Policy


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = Policy.load(ROOT / "policies" / "hardened.json")

    def test_secret_read_is_denied_in_tainted_context(self):
        action = Action(1, "secret.read", "honey/token")
        decision = self.policy.evaluate(action, {"tainted": True})
        self.assertEqual("deny", decision.effect)
        self.assertEqual("AFR-P001", decision.rule_id)

    def test_regular_internal_read_is_allowed(self):
        action = Action(1, "file.read", "repo/src/app.py")
        decision = self.policy.evaluate(action, {"tainted": False})
        self.assertEqual("allow", decision.effect)
        self.assertIsNone(decision.rule_id)


if __name__ == "__main__":
    unittest.main()
