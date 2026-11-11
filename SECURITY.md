# Security policy

## Scope

`docklint` reads untrusted build context: a Dockerfile, a compose file and a
`.dockerignore` can come from any contributor, and CI runs the scanner over
whole repositories. The parsers are therefore part of the attack surface: a
crafted file must not be able to hang the scanner, allocate without bound,
or execute anything.

What is in scope:

- a Dockerfile, compose or `.dockerignore` that crashes the tool, hangs it,
  or makes it allocate without bound;
- a file that makes the tool report *fewer* findings than it should (a
  parsing bug that silently skips a stage is a security bug, not a quality
  issue);
- a finding wrong enough to make a reader weaken a build (dropping a
  `USER`, widening a `COPY`, accepting a `latest` tag the rule was meant to
  catch);
- any path where scanning a repository can write outside the output
  location.

What is not in scope:

- rules that fire on a pattern you consider acceptable - open an issue;
- the absence of a rule you would like (a PR with a sample file is welcome);
- anything that requires building or running the image.

## Reporting

Open a private security advisory on GitHub (`Security` -> `Advisories` ->
`New draft advisory`). Include the offending file or a minimal reproducer -
a ten-line Dockerfile is usually enough.

Expect an initial response within a week. This is a single-maintainer
project, not a product with an SLA.

## Supported versions

The latest release. Old releases will be told to upgrade rather than
patched.
