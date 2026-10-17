import { describe, it, expect } from 'vitest';
import { computeClientRisk, DEFAULT_WHAT_IF_PARAMS } from './formula';

describe('Formula Parity with Server v1.2.0', () => {
  // Ground truth benchmark expectations from eval_results.json / eval.py
  const benchmarkCases = [
    {
      id: 'CVE-2023-SLEEPER-01',
      components: {
        cvss_norm: 0.765,
        exposure: 1.0,
        sensitivity: 1.0,
        blast: 0.60,
        critical_path_multiplier: 1.6,
      },
      expectedServerScore: 7.34,
      isSleeper: true,
    },
    {
      id: 'CVE-2023-SLEEPER-02',
      components: {
        cvss_norm: 0.795,
        exposure: 1.0,
        sensitivity: 1.0,
        blast: 0.60,
        critical_path_multiplier: 1.6,
      },
      expectedServerScore: 7.63,
      isSleeper: true,
    },
    {
      id: 'CVE-2023-SLEEPER-03',
      components: {
        cvss_norm: 0.805,
        exposure: 1.0,
        sensitivity: 1.0,
        blast: 0.60,
        critical_path_multiplier: 1.6,
      },
      expectedServerScore: 7.73,
      isSleeper: true,
    },
    {
      id: 'CVE-2021-DECOY-01',
      components: {
        cvss_norm: 0.99,
        exposure: 0.20,
        sensitivity: 0.25,
        blast: 0.60,
        critical_path_multiplier: 1.0,
      },
      expectedServerScore: 0.30,
      isSleeper: false,
    },
    {
      id: 'CVE-2022-DECOY-02',
      components: {
        cvss_norm: 0.99,
        exposure: 0.20,
        sensitivity: 0.25,
        blast: 0.60,
        critical_path_multiplier: 1.0,
      },
      expectedServerScore: 0.30,
      isSleeper: false,
    },
    {
      id: 'CVE-2023-DECOY-03',
      components: {
        cvss_norm: 0.98,
        exposure: 0.20,
        sensitivity: 0.25,
        blast: 0.60,
        critical_path_multiplier: 1.0,
      },
      expectedServerScore: 0.29,
      isSleeper: false,
    },
  ];

  benchmarkCases.forEach((tc) => {
    it(`calculates exact parity for ${tc.id}`, () => {
      const calculated = computeClientRisk(tc.components, DEFAULT_WHAT_IF_PARAMS);
      expect(calculated).toBeCloseTo(tc.expectedServerScore, 2);
    });
  });

  it('preserves sleeper > decoy separation under default parameters', () => {
    const sleeperScores = benchmarkCases
      .filter((c) => c.isSleeper)
      .map((c) => computeClientRisk(c.components, DEFAULT_WHAT_IF_PARAMS));
    const decoyScores = benchmarkCases
      .filter((c) => !c.isSleeper)
      .map((c) => computeClientRisk(c.components, DEFAULT_WHAT_IF_PARAMS));

    const minSleeper = Math.min(...sleeperScores);
    const maxDecoy = Math.max(...decoyScores);

    expect(minSleeper).toBeGreaterThan(maxDecoy);
    expect(minSleeper - maxDecoy).toBeGreaterThan(6.0); // Over 6 points separation margin
  });

  it('reweights correctly under what-if exposure floor increase', () => {
    const decoy = benchmarkCases.find((c) => c.id === 'CVE-2021-DECOY-01')!;
    const higherExposureFloor = { ...DEFAULT_WHAT_IF_PARAMS, exposureFloor: 0.50 };
    const elevated = computeClientRisk(decoy.components, higherExposureFloor);
    expect(elevated).toBeGreaterThan(0.30);
  });
});
