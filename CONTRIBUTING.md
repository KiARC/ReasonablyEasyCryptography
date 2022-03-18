Please use `commitizen` to format your commits. It can be installed with the
command `npm i -g commitizen cz-conventional-changelog`. Then, add the following to `~/.czrc`:

```json
{
  "path": "cz-conventional-changelog"
}
```

After that, commits can be made with the command `git cz [arguments]`.

For reference, here is a table which explains how SemVers are calculated:

| Commit Type     | Version Level |
|:----------------|--------------:|
| Breaking Change |         Major |
| Feature         |         Minor |
| Revert          |         Patch |
| Fix             |         Patch |
| Performance     |         Patch |
| Documentation   |           N/A |
| Style           |           N/A |
| Refactor        |           N/A |
| Test            |           N/A |
| Build           |           N/A |
| CI              |           N/A |
| Chore           |           N/A |