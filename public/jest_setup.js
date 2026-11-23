// EuiDataGrid is virtualized: outside a real browser it measures a 0x0
// container and renders no cells at all. Its (OUI) build detects Jest with
// `global.hasOwnProperty('_isJest')` and then renders every row, which is
// what the queue-grid tests need. OSD's own jest config sets this global in
// its setup; the plugin runs jest directly, so it sets it here.
global._isJest = true;
