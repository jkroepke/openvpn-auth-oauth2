# Documentation of openvpn-auth-oauth2

With the exception of this `README.md`, Markdown files in this directory are
published to the
[openvpn-auth-oauth2 GitHub Wiki](https://github.com/jkroepke/openvpn-auth-oauth2/wiki).

> [!NOTE]
> `.github/workflows/wiki.yaml` explicitly excludes `docs/README.md`. This file
> documents the source directory for repository contributors and never becomes
> a wiki page.

- `Home.md` is the wiki landing page.
- `_Sidebar.md` defines the task-oriented navigation shown on every page.
- `_Footer.md` links readers back to the repository where documentation changes
  are reviewed.
- `Getting Started.md` is the first-deployment journey. Detailed pages should
  remain focused references and link back to it when helpful.

The publishing workflow removes the first line of each published Markdown file
because GitHub Wiki displays the page name separately. Keep the page title on
the first line of ordinary content pages, so the source files are readable in
the repository. The special `_Footer.md` file starts with an empty line instead.

When adding or renaming a page, update `Home.md` and `_Sidebar.md`. Use relative
wiki links without a `.md` suffix, and replace spaces with `%20`, for example:

```markdown
[Getting Started](Getting%20Started)
```
