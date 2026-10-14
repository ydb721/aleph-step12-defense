export function changedFilesForCommit(git, commit) {
  const [, firstParent] = git('rev-list', '--parents', '-n', '1', commit).split(/\s+/u);
  const output = firstParent
    ? git('diff', '--name-only', '--no-renames', firstParent, commit)
    : git('diff-tree', '--root', '--no-commit-id', '--name-only', '--no-renames', '-r', commit);
  return output.split(/\r?\n/u).filter(Boolean).sort();
}
