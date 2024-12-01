# Layout Customization

openvpn-auth-oauth2 supports custom templates for the login page.
The template must a valid Go Template file.
After rendering, valid HTML must be returned.

The default template can be found here:
[index.gohtml](https://github.com/jkroepke/openvpn-auth-oauth2/blob/main/internal/ui/index.gohtml)

Available variables:

- `{{.title}}`: `Access denied` or `Access granted`
- `{{.message}}`: Potential error message or success message
- `{{.errorID}}`: ErrorID of an error, if present

The [go template engine](https://pkg.go.dev/text/template) is used to render the HTML file.

## Overriding the default assets

To override the default assets, you can configure `http.assets-path` with the path to the directory containing the assets.

The default assets are here:

- `style.css`: CSS file to enrich the default layout. By default, it is empty.
- `mvp.css`: [MVP](https://github.com/andybrewer/mvp) css framework
- `favicon.png`: Favicon of the login page
- `i18n.js`: Localization script
- `i18n/<lang>.json`: Language specific localization file. <lang> is the language code, e.g., `en` for English.
  See [de.json](https://github.com/jkroepke/openvpn-auth-oauth2/blob/main/internal/ui/static/i18n/de.json) for an example.

## Custom localization

If you want to provide custom localization, you have to configure `http.assets-path` first. In the assets directory,
create a new directory named `i18n` and put your localization files in there. The file name must be the language code
followed by `.json`. For example, `en.json` for English.

Instead, providing a custom localization file locally, think about to submit a pull request to the project to provide
the localization for everyone.
