export function changedFilesForCommit(git, commit) {
  const output = git('show', '--first-parent', '--format=', '--name-only', '--no-renames', commit);
  return output.split(/\r?\n/u).filter(Boolean).sort();
}
