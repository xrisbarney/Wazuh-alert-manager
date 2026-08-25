// Our mark, inlined as a data URI (same artwork as public/assets/logo.svg).
//
// It lives in its own module rather than in plugin.ts so components can use it
// without importing the plugin class - plugin.ts already imports ./application,
// which imports the components, so pulling it from there would be a cycle.
//
// Used with EuiIcon, which handles data URIs. Note the side nav does NOT: it
// renders a URL-valued `icon` as a plain <img> that showed a broken-image
// placeholder, so the nav entry uses a named `euiIconType` glyph instead.
export const PLUGIN_LOGO_DATA_URI =
  'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzIiIGhlaWdodD0iMzIiIHZpZXdCb3g9IjAgMCAzMiAzMiIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICA8cGF0aCBkPSJNMTYgMiBMMjggNi41IFYxNSBDMjggMjIuNSAyMi44IDI3LjggMTYgMzAgQzkuMiAyNy44IDQgMjIuNSA0IDE1IFY2LjUgWiIKICAgICAgICBmaWxsPSIjMEI2NEREIi8+CiAgPHBhdGggZD0iTTE2IDIgTDI4IDYuNSBWMTUgQzI4IDIyLjUgMjIuOCAyNy44IDE2IDMwIFoiCiAgICAgICAgZmlsbD0iIzA3NEZCMyIvPgogIDxwYXRoIGQ9Ik0xNiA4LjUgTDE2IDE4IiBzdHJva2U9IiNGRkZGRkYiIHN0cm9rZS13aWR0aD0iMi42IiBzdHJva2UtbGluZWNhcD0icm91bmQiLz4KICA8Y2lyY2xlIGN4PSIxNiIgY3k9IjIyLjUiIHI9IjEuOCIgZmlsbD0iI0ZGRkZGRiIvPgogIDxjaXJjbGUgY3g9IjI0IiBjeT0iOS41IiByPSIzLjIiIGZpbGw9IiNGNUE2MjMiLz4KPC9zdmc+Cg==';
