// Gera public/icons.js a partir dos SVGs Lucide copiados (so o miolo do <svg>).
const fs = require('fs'), path = require('path');
const dir = path.join(__dirname, 'public', 'vendor', 'icons');
const out = {};
for (const f of fs.readdirSync(dir)) {
  if (!f.endsWith('.svg')) continue;
  const s = fs.readFileSync(path.join(dir, f), 'utf8');
  const inner = s.replace(/<!--[\s\S]*?-->/g, '').replace(/^[\s\S]*?>\s*(?=<(path|circle|rect|line|polyline|polygon|ellipse))/, '').replace(/<\/svg>\s*$/, '').replace(/\s+/g, ' ').trim();
  out[f.replace('.svg', '')] = inner;
}
fs.writeFileSync(path.join(__dirname, 'public', 'icons.js'), 'window.ICONS=' + JSON.stringify(out) + ';\n');
console.log(Object.keys(out).length + ' icones');
