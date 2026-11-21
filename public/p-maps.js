'use strict';
// Mapas: satélite, aviação, clima e ameaças reais. Tudo passa pelo proxy do servidor.
// Tema mono: a base OSM (aviação/clima/ameaças) recebe filtro escala-de-cinza+invertido para
// combinar com o app. O satélite fica em cor verdadeira (é uma foto real, faz sentido ver assim).

const ATTR = '&copy; colaboradores do OpenStreetMap | Esri | OpenSky Network | RainViewer | blocklist.de';

function darkOsmLayer() {
  const l = L.tileLayer('/api/maps/tile/osm/{z}/{x}/{y}', { maxZoom: 19, attribution: ATTR });
  l.on('add', () => { const p = l.getPane?.() || l._map?.getPane('tilePane'); if (p) p.classList.add('map-dark-base'); });
  return l;
}

function baseMap(el, center, zoom) {
  const map = L.map(el, { zoomControl: true, attributionControl: true, preferCanvas: true }).setView(center, zoom);
  return map;
}

App.register({
  id: 'maps', title: 'Mapas', icon: 'globe',
  async render(root) {
    let tab = localStorage.getItem('maptab') || 'sat';
    root.innerHTML = App.head('Utilitários', 'Mapas', 'Satélite, aviação ao vivo, radar de chuva e IPs reportados atacando — tudo de fontes públicas e gratuitas.') + `<div class="tabs" id="mt"><button data-t="sat">${icon('globe', 15)} Satélite</button><button data-t="aviation">${icon('send', 15)} Aviação</button><button data-t="weather">${icon('activity', 15)} Clima</button><button data-t="threats">${icon('shield-check', 15)} Ameaças</button></div><div id="mb"></div>`;
    const show = (t) => { tab = t; localStorage.setItem('maptab', t); $$('#mt button').forEach((b) => b.classList.toggle('on', b.dataset.t === t)); App.runCleanups(); ({ sat: tabSat, aviation: tabAviation, weather: tabWeather, threats: tabThreats })[t]($('#mb')); };
    $$('#mt button').forEach((b) => b.onclick = () => show(b.dataset.t)); show(tab);
  },
});

function tabSat(box) {
  box.innerHTML = `<div class="card"><div id="map-sat" style="height:calc(100vh - 260px);min-height:420px;border-radius:var(--r)"></div></div>`;
  const map = baseMap('map-sat', [-14.2, -51.9], 4);
  L.tileLayer('/api/maps/tile/sat/{z}/{x}/{y}', { maxZoom: 19, attribution: ATTR }).addTo(map);
  L.tileLayer('/api/maps/tile/sat-ref/{z}/{x}/{y}', { maxZoom: 19, opacity: 0.9 }).addTo(map);
  App.leave(() => map.remove());
}

function planeIcon(heading) {
  return L.divIcon({ className: 'plane-ic', html: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.6" style="transform:rotate(${heading || 0}deg)"><path d="M12 2 L15 10 L22 13 L15 14.5 L14 22 L12 18 L10 22 L9 14.5 L2 13 L9 10 Z" fill="#fff" fill-opacity="0.9"/></svg>`, iconSize: [20, 20], iconAnchor: [10, 10] });
}

function tabAviation(box) {
  box.innerHTML = `<div class="card"><div class="card-head"><div class="row"><i class="dot run" id="av-dot"></i><h2>Tráfego aéreo ao vivo</h2><span class="hint">fonte: OpenSky Network, anônimo</span></div><span class="hint mono" id="av-n">-</span></div><div id="map-av" style="height:calc(100vh - 310px);min-height:380px"></div></div>`;
  const map = baseMap('map-av', [-23.5, -46.6], 7);
  darkOsmLayer().addTo(map);
  const markers = new Map();
  let timer = null; let busy = false;
  async function refresh() {
    if (busy) return; busy = true; $('#av-dot').className = 'dot run';
    try {
      const b = map.getBounds();
      const r = await get(`/api/maps/aviation?lamin=${b.getSouth()}&lomin=${b.getWest()}&lamax=${b.getNorth()}&lomax=${b.getEast()}`);
      const seen = new Set();
      for (const p of r.planes) {
        seen.add(p.icao);
        const label = p.callsign || p.icao;
        if (markers.has(p.icao)) { const m = markers.get(p.icao); m.setLatLng([p.lat, p.lon]); m.setIcon(planeIcon(p.heading)); m.setPopupContent(popupHtml(p)); }
        else { const m = L.marker([p.lat, p.lon], { icon: planeIcon(p.heading) }).bindPopup(popupHtml(p)).addTo(map); markers.set(p.icao, m); }
      }
      for (const [k, m] of [...markers]) if (!seen.has(k)) { map.removeLayer(m); markers.delete(k); }
      $('#av-n').textContent = `${r.planes.length} aeronave(s) na área visível`;
      $('#av-dot').className = 'dot ok';
    } catch (e) { $('#av-dot').className = 'dot bad'; $('#av-n').textContent = e.message; }
    finally { busy = false; }
  }
  function popupHtml(p) { return `<b>${esc(p.callsign || p.icao)}</b><br>País: ${esc(p.country || '-')}<br>Altitude: ${p.altitude != null ? Math.round(p.altitude) + ' m' : '-'}<br>Velocidade: ${p.velocity != null ? Math.round(p.velocity * 3.6) + ' km/h' : '-'}`; }
  map.on('moveend', () => { clearTimeout(timer); timer = setTimeout(refresh, 600); });
  refresh(); const iv = setInterval(refresh, 15000);
  App.leave(() => { clearInterval(iv); clearTimeout(timer); map.remove(); });
}

function tabWeather(box) {
  box.innerHTML = `<div class="card"><div class="card-head"><div class="row"><i class="dot" id="we-dot"></i><h2>Radar de precipitação</h2><span class="hint">fonte: RainViewer</span></div><div class="row"><button class="btn sm icon" id="we-play" aria-label="Reproduzir">${icon('play', 14)}</button><input type="range" id="we-slider" min="0" max="0" value="0" style="width:180px;accent-color:var(--ac)"><span class="hint mono" id="we-t">-</span></div></div><div id="map-we" style="height:calc(100vh - 310px);min-height:380px"></div></div>`;
  const map = baseMap('map-we', [-14.2, -51.9], 4);
  darkOsmLayer().addTo(map);
  let weatherLayer = null; let frames = []; let idx = 0; let playing = false; let playTimer = null;
  (async () => {
    try {
      const meta = await get('/api/maps/weather/meta'); frames = meta.frames; idx = frames.length - 1;
      $('#we-slider').max = String(frames.length - 1); $('#we-slider').value = String(idx);
      weatherLayer = L.tileLayer(`/api/maps/weather/tile/${idx}/{z}/{x}/{y}`, { opacity: 0.65, maxZoom: 12 }).addTo(map);
      setFrameLabel(); $('#we-dot').className = 'dot ok';
    } catch (e) { $('#we-dot').className = 'dot bad'; toast(e.message, 'bad'); }
  })();
  function setFrameLabel() { const f = frames[idx]; $('#we-t').textContent = f ? new Date(f.time * 1000).toLocaleTimeString('pt-BR') : '-'; }
  function setFrame(i) { idx = Math.max(0, Math.min(frames.length - 1, i)); weatherLayer?.setUrl(`/api/maps/weather/tile/${idx}/{z}/{x}/{y}`); $('#we-slider').value = String(idx); setFrameLabel(); }
  $('#we-slider').oninput = (e) => setFrame(+e.target.value);
  $('#we-play').onclick = () => {
    playing = !playing; $('#we-play').innerHTML = icon(playing ? 'pause' : 'play', 14);
    if (playing) playTimer = setInterval(() => setFrame(idx + 1 >= frames.length ? 0 : idx + 1), 700); else clearInterval(playTimer);
  };
  App.leave(() => { clearInterval(playTimer); map.remove(); });
}

const SEV_COLOR = (n) => (n >= 4 ? '#fff' : n >= 2 ? '#bbb' : '#777');

async function tabThreats(box) {
  box.innerHTML = `<div class="notice" style="margin-bottom:16px">${icon('info')}<div><b>O que é isto:</b> IPs que servidores reais reportaram sofrendo ataque (SSH, e-mail, formulários web, bots) nas últimas ~48h. Fonte: <code>blocklist.de</code>, um projeto comunitário gratuito. Não é um "ataque ao vivo" — é o que já foi reportado.</div></div>
    <div class="card"><div class="card-head"><div class="row"><h2>Mapa de IPs reportados</h2><span class="hint mono" id="th-info">-</span></div><button class="btn sm" id="th-refresh">${icon('refresh-cw', 14)} Atualizar</button></div>
    <div id="map-th" style="height:calc(100vh - 360px);min-height:360px"></div>
    <div class="console hide" id="th-log" style="height:110px;border:0;border-top:1px solid var(--line);border-radius:0"></div></div>`;
  const map = baseMap('map-th', [20, 0], 2);
  darkOsmLayer().addTo(map);
  const layer = L.layerGroup().addTo(map);

  function draw(state) {
    layer.clearLayers();
    if (!state) { $('#th-info').textContent = 'sem dados ainda'; return; }
    for (const p of state.points) {
      const r = 4 + Math.min(6, p.score);
      L.circleMarker([p.lat, p.lon], { radius: r, color: '#fff', weight: 1, fillColor: SEV_COLOR(p.score), fillOpacity: 0.55 })
        .bindPopup(`<b class="mono">${esc(p.ip)}</b><br>${esc(p.city || '?')}, ${esc(p.country || '?')}<br>${esc(p.org || '')}<br>Categorias: ${p.categories.map((c) => esc(MAPS_BL_LEGEND[c] || c)).join(', ')}`)
        .addTo(layer);
    }
    $('#th-info').textContent = `${state.points.length} IP(s) · atualizado ${fmtTime(state.generatedAt)}`;
  }

  let MAPS_BL_LEGEND = {};
  const r0 = await safe(() => get('/api/maps/threats')); if (r0) { MAPS_BL_LEGEND = r0.legend; draw(r0.state); }

  $('#th-refresh').onclick = async (e) => {
    const r = await safe(() => post('/api/maps/threats/refresh'), e.currentTarget); if (!r) return;
    const log = $('#th-log'); log.classList.remove('hide');
    await watchJob(r.job, log);
    const r2 = await safe(() => get('/api/maps/threats')); if (r2) draw(r2.state);
  };
  App.leave(() => map.remove());
}
