import unittest

from run_empirical_validation import EXPECTED, evaluate, generate_chunks, generate_pairs


class EmpiricalValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chunks = generate_chunks()
        cls.pairs = generate_pairs()

    def test_registered_sample_sizes(self):
        self.assertEqual(len(self.chunks), EXPECTED["chunks"])
        self.assertEqual(len({pair.parent_id for pair in self.pairs}), EXPECTED["parent_queries"])
        self.assertEqual(len(self.pairs), EXPECTED["contrast_queries"])
        self.assertEqual(sum(pair.axis != "V2" for pair in self.pairs), EXPECTED["invariant_pairs"])

    def test_prefilter_has_no_unauthorized_intermediate_candidates(self):
        metrics, _ = evaluate(self.chunks, self.pairs, "S5")
        self.assertEqual(metrics["intermediate_leakage_pair_rate"], 0)
        self.assertEqual(metrics["final_leakage_pair_rate"], 0)

    def test_postfilter_exposes_intermediate_candidates(self):
        metrics, _ = evaluate(self.chunks, self.pairs, "S4")
        self.assertGreater(metrics["intermediate_leakage_pair_rate"], 0)
        self.assertEqual(metrics["final_leakage_pair_rate"], 0)


if __name__ == "__main__":
    unittest.main()
