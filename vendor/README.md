# Vendored source references

`vendor/sabledb` is a Git submodule of the public
[`rusty-auth/sabledb`](https://github.com/rusty-auth/sabledb) fork. The parent RustyAuth commit pins one exact
SableDB revision; container builds compile that checkout directly, so source changes can be tested locally
before the parent gitlink moves.

Initialize an existing clone:

```sh
git submodule update --init --recursive
```

To work on SableDB from inside a RustyAuth checkout:

```sh
cd vendor/sabledb
git switch -c fix/descriptive-name
git remote add upstream https://github.com/sabledb-io/sabledb.git
# edit, test, commit, then publish the branch to the RustyAuth fork
git push -u origin HEAD
```

Open the SableDB pull request from that branch. It can target the RustyAuth fork for integration work or the
upstream `sabledb-io/sabledb` repository for a generally useful fix. After its commit is available from the
public fork, return to the RustyAuth root, stage `vendor/sabledb`, and commit the gitlink update. Never commit a
dirty submodule or point the parent at a commit that anonymous CI cannot fetch.

Use `git submodule update --remote vendor/sabledb` only when intentionally reviewing a newer fork `main`.
Normal builds use the revision pinned by the parent repository, not the branch tip.
