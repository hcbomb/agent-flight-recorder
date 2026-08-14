from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_flight_recorder.engine import run_scenario
from agent_flight_recorder.models import Scenario
from agent_flight_recorder.policy import Policy
from agent_flight_recorder.rules import load_rules


class ReplayEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules(ROOT / "rules" / "detections.json")
        cls.baseline = Policy.load(ROOT / "policies" / "baseline.json")
        cls.hardened = Policy.load(ROOT / "policies" / "hardened.json")

    def scenarios(self):
        return [Scenario.load(path) for path in sorted((ROOT / "scenarios").glob("*.json"))]

    def test_baseline_allows_each_attack_goal(self):
        for scenario in self.scenarios():
            with self.subTest(scenario=scenario.id):
                result = run_scenario(scenario, self.baseline, self.rules)
                self.assertTrue(result.attack_success)
                self.assertEqual("COMPROMISED", result.status)
                self.assertGreaterEqual(len(result.detections), 1)

    def test_hardened_policy_contains_each_attack(self):
        for scenario in self.scenarios():
            with self.subTest(scenario=scenario.id):
                result = run_scenario(scenario, self.hardened, self.rules)
                self.assertFalse(result.attack_success)
                self.assertTrue(result.blocked)
                self.assertEqual("CONTAINED", result.status)
                self.assertGreaterEqual(len(result.detections), 1)

    def test_trace_id_is_deterministic(self):
        scenario = self.scenarios()[0]
        first = run_scenario(scenario, self.baseline, self.rules)
        second = run_scenario(scenario, self.baseline, self.rules)
        self.assertEqual(first.trace_id, second.trace_id)
        self.assertEqual(first.as_dict(), second.as_dict())


if __name__ == "__main__":
    unittest.main()
