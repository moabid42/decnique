/**
 * The commit convention from AGENTS.md §8, made enforceable:
 *
 *     type(scope): what and why
 *
 * one line, atomic, no trailers.  Conventional Commits gives the `type(scope):` shape; the
 * three rules below add the parts that are specific to this repository — the type list it
 * actually uses, "one line" (no body), and the trailer ban.
 *
 * Reverts are exempt: `git revert` writes its own multi-line message and there is no reason to
 * fight it.  Merge commits are exempt by commitlint's own defaults.
 */

/** A local plugin: AGENTS.md §8 says commits carry no trailers, so say so at the hook. */
const noTrailers = {
  rules: {
    'no-trailers': ({ raw }) => {
      const banned =
        /^(Co-authored-by|Signed-off-by|Claude-Session|Generated-with|Reviewed-by)\s*:/im;
      const hit = banned.exec(raw ?? '');
      return [
        hit === null,
        `AGENTS.md §8: commits carry no trailers — drop the "${hit ? hit[1] : ''}" line`,
      ];
    },
  },
};

module.exports = {
  extends: ['@commitlint/config-conventional'],
  plugins: [noTrailers],
  ignores: [(message) => /^(revert|Revert)[: ]/.test(message)],
  rules: {
    'no-trailers': [2, 'always'],
    // the types this repository actually uses, plus the two it has not needed yet
    'type-enum': [
      2,
      'always',
      ['feat', 'fix', 'docs', 'test', 'refactor', 'perf', 'chore', 'ci', 'build', 'revert'],
    ],
    'header-max-length': [2, 'always', 100],
    'subject-full-stop': [2, 'never', '.'],
    // "one line": the subject says what and why, so there is nothing left for a body
    'body-empty': [2, 'always'],
    'footer-empty': [2, 'always'],
  },
};
