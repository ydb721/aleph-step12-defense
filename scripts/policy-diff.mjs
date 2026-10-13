import { comparePolicy, loadVerifiedPolicy, printPolicyDiff } from './policy-lib.mjs';

try {
  const policy = loadVerifiedPolicy();
  const results = comparePolicy(policy);
  printPolicyDiff(policy, results);
} catch (error) {
  process.stderr.write(`정책 비교 중단: ${error.message}\n`);
  process.exitCode = 1;
}
