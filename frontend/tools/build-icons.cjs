// Vendor a small, static Lucide subset. No runtime CDN or npm dependency.
// Usage: node frontend/tools/build-icons.cjs /path/to/node_modules
const fs = require('node:fs');
const path = require('node:path');
const modules = path.resolve(process.argv[2]);
const react = require(path.join(modules, 'react'));
const server = require(path.join(modules, 'react-dom/server'));
const lucide = require(path.join(modules, 'lucide-react'));
const names = ['ShieldCheck', 'Crosshair', 'SquareTerminal', 'ListChecks', 'FileChartColumn',
  'PanelLeft', 'ChevronRight', 'ChevronLeft', 'Moon', 'Sun', 'Settings2', 'Layers',
  'Search', 'Plus', 'RefreshCw', 'ArrowLeft', 'ArrowRight', 'Trash2', 'Download',
  'Pause', 'Play', 'X', 'Clipboard', 'Pencil', 'RotateCcw', 'Send', 'Clock',
  'Activity', 'CircleCheck', 'CircleAlert', 'CircleDashed', 'FileSearch', 'LockKeyhole'];
const icons = Object.fromEntries(names.map(name => [name,
  server.renderToStaticMarkup(react.createElement(lucide[name], {width:18,height:18,strokeWidth:1.7}))]));
const dir = path.resolve(__dirname, '../static/js');
fs.writeFileSync(path.join(dir, 'icons.js'),
  '/* Generated Lucide subset. ISC/MIT: see /static/vendor/LUCIDE-LICENSE. */\n' +
  'const EP_ICONS = ' + JSON.stringify(icons) + ';\n' +
  'function epIcon(name) { const el = document.createElement("span"); el.className="ui-icon"; el.innerHTML=EP_ICONS[name] || EP_ICONS.CircleDashed; el.setAttribute("aria-hidden","true"); return el; }\n' +
  'function hydrateIcons(root=document) { root.querySelectorAll("[data-icon]").forEach(el=>{ el.replaceChildren(epIcon(el.dataset.icon)); }); }\n');
fs.mkdirSync(path.resolve(__dirname, '../static/vendor'), {recursive:true});
fs.copyFileSync(path.join(modules, 'lucide-react/LICENSE'), path.resolve(__dirname, '../static/vendor/LUCIDE-LICENSE'));
