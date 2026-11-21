#!/usr/bin/env python3
"""Sentinel TUI - cliente de terminal para o backend do Sentinel (Linux).

Fala com o mesmo backend Node (server.js) que a interface web usa, pela
mesma API REST. Nenhuma lógica de segurança é duplicada aqui: PIN, escopo,
cofre, apagar de emergência etc. continuam todos no servidor - esta tela
só manda e mostra.
"""
import json
import os
import sys
import threading
import time
from dataclasses import dataclass, field

try:
    import requests
except ImportError:
    print("Falta a biblioteca 'requests'. Instale com: pip install requests textual")
    sys.exit(1)

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll, Container
from textual.screen import Screen, ModalScreen
from textual.widgets import (
    Static, Button, Input, ListView, ListItem, Label, DataTable,
    RichLog, Switch, LoadingIndicator, Select,
)
from textual.binding import Binding
from textual import work, on
from textual.reactive import reactive

BASE_URL = os.environ.get("SENTINEL_URL", "http://127.0.0.1:7777").rstrip("/")


class ApiError(Exception):
    pass


class Client:
    """Fala REST com o backend. Guarda o cookie de sessão na requests.Session."""

    def __init__(self, base_url: str):
        self.base = base_url
        self.s = requests.Session()
        self.s.headers.update({"X-Sentinel": "1"})

    def _req(self, method, path, json_body=None, params=None, timeout=20):
        url = f"{self.base}{path}"
        try:
            r = self.s.request(method, url, json=json_body, params=params, timeout=timeout)
        except requests.exceptions.ConnectionError as e:
            raise ApiError(f"Não consegui falar com {self.base} - o backend está rodando? ({e.__class__.__name__})")
        except requests.exceptions.Timeout:
            raise ApiError("O servidor demorou demais para responder.")
        if r.status_code >= 400:
            try:
                msg = r.json().get("error", r.text)
            except Exception:
                msg = r.text or f"HTTP {r.status_code}"
            raise ApiError(msg)
        if not r.content:
            return {}
        try:
            return r.json()
        except Exception:
            return {}

    def get(self, path, params=None):
        return self._req("GET", path, params=params)

    def post(self, path, body=None):
        return self._req("POST", path, json_body=body or {})

    def delete(self, path, body=None):
        return self._req("DELETE", path, json_body=body or {})

    def stream(self, path, on_event, stop_flag):
        """SSE: chama on_event(dict) para cada 'data:' recebido até stop_flag() ser True."""
        url = f"{self.base}{path}"
        try:
            with self.s.get(url, stream=True, timeout=(10, None)) as r:
                if r.status_code >= 400:
                    on_event({"k": "_error", "text": f"HTTP {r.status_code}"})
                    return
                for raw in r.iter_lines(decode_unicode=True):
                    if stop_flag():
                        return
                    if not raw or not raw.startswith("data:"):
                        continue
                    payload = raw[5:].strip()
                    try:
                        ev = json.loads(payload)
                    except Exception:
                        continue
                    on_event(ev)
        except requests.exceptions.RequestException as e:
            on_event({"k": "_error", "text": str(e)})

    # ---- auth ----
    def auth_state(self): return self.get("/api/auth/state")
    def auth_setup(self, pin): return self.post("/api/auth/setup", {"pin": pin})
    def auth_login(self, pin, totp=None): return self.post("/api/auth/login", {"pin": pin, "totp": totp})
    def auth_logout(self): return self.post("/api/auth/logout")

    # ---- sistema ----
    def system(self): return self.get("/api/system")
    def audit(self): return self.get("/api/audit")

    # ---- escopo ----
    def scope_list(self): return self.get("/api/scope")
    def scope_add(self, value, note, attested): return self.post("/api/scope", {"value": value, "note": note, "attested": attested})
    def scope_remove(self, value): return self.delete("/api/scope", {"value": value})

    # ---- scans ----
    def scan_web(self, target, level): return self.post("/api/scan/web", {"target": target, "level": level})
    def scan_ports(self, target, ports): return self.post("/api/scan/ports", {"target": target, "ports": ports})
    def scan_history(self): return self.get("/api/scan/history")

    # ---- ferramentas ----
    def tools_status(self): return self.get("/api/tools")
    def tools_run(self, tool, params): return self.post("/api/tools/run", {"tool": tool, "params": params})
    def tools_install(self, tool): return self.post("/api/tools/install", {"tool": tool})

    # ---- jobs ----
    def job_get(self, jid): return self.get(f"/api/jobs/{jid}")
    def job_kill(self, jid): return self.post(f"/api/jobs/{jid}/kill")

    # ---- cofre ----
    def vault_password(self, **kw): return self.post("/api/vault/password", kw)
    def vault_passphrase(self, words): return self.post("/api/vault/passphrase", {"words": words})
    def vault_encrypt(self, path, password, remove): return self.post("/api/vault/encrypt", {"path": path, "password": password, "removeOriginal": remove})
    def vault_decrypt(self, path, password): return self.post("/api/vault/decrypt", {"path": path, "password": password})

    # ---- applock ----
    def applock_state(self): return self.get("/api/applock")
    def applock_add(self, exe): return self.post("/api/applock/add", {"exe": exe})
    def applock_remove(self, name): return self.post("/api/applock/remove", {"name": name})
    def applock_idle(self, minutes): return self.post("/api/applock/idle", {"min": minutes})
    def applock_lock(self): return self.post("/api/applock/lock")
    def applock_unlock(self, pin): return self.post("/api/applock/unlock", {"pin": pin})

    # ---- apagar de emergencia ----
    def panic_state(self): return self.get("/api/panic")
    def panic_presets(self): return self.get("/api/panic/presets")
    def panic_target_add(self, path, note): return self.post("/api/panic/target", {"path": path, "note": note})
    def panic_target_remove(self, path): return self.delete("/api/panic/target", {"path": path})
    def panic_overwrite(self, on): return self.post("/api/panic/overwrite", {"on": on})
    def panic_preview(self): return self.get("/api/panic/preview")
    def panic_execute(self, pin, confirm): return self.post("/api/panic/execute", {"pin": pin, "confirm": confirm})
    def panic_backup(self, dest, password): return self.post("/api/panic/backup", {"dest": dest, "password": password})
    def panic_selfdestruct(self, pin, confirm): return self.post("/api/panic/selfdestruct", {"pin": pin, "confirm": confirm})

    # ---- notas ----
    def notes_list(self): return self.get("/api/notes")
    def notes_upsert(self, nid, title, body): return self.post("/api/notes", {"id": nid, "title": title, "body": body})
    def notes_remove(self, nid): return self.delete("/api/notes", {"id": nid})

    # ---- mapas (só dado, sem tiles - isso e visual, fica pro navegador) ----
    def maps_threats(self): return self.get("/api/maps/threats")
    def maps_threats_refresh(self): return self.post("/api/maps/threats/refresh")

    # ---- VMs ----
    def vm_providers(self): return self.get("/api/vm/providers")
    def vm_list(self): return self.get("/api/vm/list")
    def vm_action(self, provider, name, action): return self.post("/api/vm/action", {"provider": provider, "name": name, "action": action})

    # ---- rede ----
    def geoip(self, q): return self.get("/api/geoip", {"q": q} if q else None)
    def tempmail_list(self): return self.get("/api/tempmail")
    def tempmail_create(self): return self.post("/api/tempmail")
    def tempmail_messages(self, addr): return self.get("/api/tempmail/messages", {"address": addr})
    def tempmail_delete(self, addr): return self.delete("/api/tempmail", {"address": addr})
    def proxy_system_get(self): return self.get("/api/proxy/system")
    def proxy_list(self): return self.get("/api/proxy/list")
    def proxy_add(self, **kw): return self.post("/api/proxy/list", kw)
    def proxy_remove(self, pid): return self.delete("/api/proxy/list", {"id": pid})
    def proxy_test(self, pid): return self.post("/api/proxy/test", {"id": pid})

    # ---- IA ----
    def ai_status(self): return self.get("/api/ai/status")
    def ai_settings(self): return self.get("/api/ai/settings")
    def ai_save_settings(self, **kw): return self.post("/api/ai/settings", kw)
    def ai_serve(self): return self.post("/api/ai/serve")
    def ai_pull(self, model): return self.post("/api/ai/pull", {"model": model})

    # ---- agentes ----
    def agents_list(self): return self.get("/api/agents")
    def agents_autonomy(self, agent, mode, pin=None): return self.post("/api/agents/autonomy", {"agent": agent, "mode": mode, "pin": pin})
    def agents_session_new(self, agent): return self.post("/api/agents/sessions", {"agent": agent})
    def agents_session_send(self, sid, text): return self.post(f"/api/agents/sessions/{sid}/send", {"text": text})
    def agents_session_stop(self, sid): return self.post(f"/api/agents/sessions/{sid}/stop")
    def agents_session_remove(self, sid): return self.delete(f"/api/agents/sessions/{sid}")
    def agents_approve(self, aid, approve): return self.post("/api/agents/approve", {"id": aid, "approve": approve})

    # ---- remoto / lab ----
    def remote_get(self): return self.get("/api/remote")
    def remote_set(self, **kw): return self.post("/api/remote", kw)
    def lab_state(self): return self.get("/api/lab")
    def lab_start(self): return self.post("/api/lab/start")
    def lab_stop(self): return self.post("/api/lab/stop")


CSS = """
Screen { background: #000000; color: #e9e9e9; }
#login-box, #setup-box { border: round #ffffff; padding: 2 4; width: 60; height: auto; align: center middle; }
#sidebar { width: 26; background: #000000; border-right: solid #333333; }
#sidebar ListView { background: #000000; }
#sidebar ListItem { padding: 0 1; color: #9a9a9a; }
#sidebar ListItem.-highlight { background: #1a1a1a; color: #ffffff; }
#content { padding: 1 2; }
.title { color: #ffffff; text-style: bold; }
.hint { color: #777777; }
.danger { color: #ff5c5c; }
.ok { color: #7fffa0; }
Button { background: #111111; color: #e9e9e9; border: round #555555; }
Button:hover { background: #222222; border: round #ffffff; }
Button.-primary { border: round #ffffff; color: #ffffff; }
Button.-danger { border: round #ff5c5c; color: #ff8080; }
Input { background: #0a0a0a; color: #e9e9e9; border: round #444444; }
Input:focus { border: round #ffffff; }
DataTable { background: #000000; }
RichLog { background: #050505; border: round #333333; }
.row { height: auto; }
.card { border: round #333333; padding: 1 2; margin-bottom: 1; }
"""


class PinModal(ModalScreen):
    """Pede PIN (e opcionalmente uma palavra de confirmação) antes de uma ação sensível."""

    def __init__(self, title, confirm_word=None, danger=False):
        super().__init__()
        self.title_text = title
        self.confirm_word = confirm_word
        self.danger = danger
        self.result_value = None

    def compose(self) -> ComposeResult:
        with Vertical(id="login-box"):
            yield Static(self.title_text, classes="title danger" if self.danger else "title")
            if self.confirm_word:
                yield Static(f"Digite {self.confirm_word} para confirmar:", classes="hint")
                yield Input(placeholder=self.confirm_word, id="confirm-word")
            yield Static("PIN:", classes="hint")
            yield Input(placeholder="PIN", password=True, id="pin-input")
            with Horizontal():
                yield Button("Cancelar", id="cancel")
                yield Button("Confirmar", id="ok", classes="-danger" if self.danger else "-primary")

    @on(Button.Pressed, "#cancel")
    def _cancel(self):
        self.dismiss(None)

    @on(Button.Pressed, "#ok")
    def _ok(self):
        pin = self.query_one("#pin-input", Input).value
        word = self.query_one("#confirm-word", Input).value if self.confirm_word else None
        self.dismiss({"pin": pin, "word": word})

    @on(Input.Submitted)
    def _submit(self):
        self._ok()


class TextModal(ModalScreen):
    """Modal simples: um título, um Input, Cancelar/OK."""

    def __init__(self, title, placeholder="", password=False):
        super().__init__()
        self.title_text = title
        self.placeholder = placeholder
        self.password = password

    def compose(self) -> ComposeResult:
        with Vertical(id="login-box"):
            yield Static(self.title_text, classes="title")
            yield Input(placeholder=self.placeholder, password=self.password, id="val")
            with Horizontal():
                yield Button("Cancelar", id="cancel")
                yield Button("OK", id="ok", classes="-primary")

    @on(Button.Pressed, "#cancel")
    def _cancel(self):
        self.dismiss(None)

    @on(Button.Pressed, "#ok")
    def _ok(self):
        self.dismiss(self.query_one("#val", Input).value)

    @on(Input.Submitted)
    def _submit(self):
        self._ok()


class LoginScreen(Screen):
    def __init__(self, client: Client, state: dict):
        super().__init__()
        self.client = client
        self.state = state

    def compose(self) -> ComposeResult:
        setup = not self.state.get("setup")
        with Vertical(id="setup-box" if setup else "login-box"):
            yield Static("SENTINEL", classes="title")
            yield Static(BASE_URL, classes="hint")
            if setup:
                yield Static("Primeiro acesso: crie um PIN (6+ dígitos).", classes="hint")
                yield Input(placeholder="Novo PIN", password=True, id="pin")
                yield Button("Criar PIN", id="go", classes="-primary")
            else:
                yield Input(placeholder="PIN", password=True, id="pin")
                if self.state.get("needs2fa"):
                    yield Input(placeholder="Código 2FA", id="totp")
                yield Button("Entrar", id="go", classes="-primary")
            yield Static("", id="msg", classes="danger")

    @on(Button.Pressed, "#go")
    def _go(self):
        self._attempt()

    @on(Input.Submitted)
    def _submit(self):
        self._attempt()

    def _attempt(self):
        pin = self.query_one("#pin", Input).value
        setup = not self.state.get("setup")
        try:
            if setup:
                r = self.client.auth_setup(pin)
                self.app.push_screen(RecoveryScreen(r.get("recovery", "")))
                return
            totp_input = self.query("#totp")
            totp = totp_input.first().value if totp_input else None
            self.client.auth_login(pin, totp)
        except ApiError as e:
            self.query_one("#msg", Static).update(str(e))
            return
        self.app.after_login()


class RecoveryScreen(Screen):
    def __init__(self, code):
        super().__init__()
        self.code = code

    def compose(self) -> ComposeResult:
        with Vertical(id="setup-box"):
            yield Static("Guarde seu código de recuperação", classes="title")
            yield Static("Ele só aparece uma vez. Sem ele, se esquecer o PIN, não tem como recuperar o acesso.", classes="hint")
            yield Static(self.code, classes="ok")
            yield Button("Já salvei, continuar", id="go", classes="-primary")

    @on(Button.Pressed, "#go")
    def _go(self):
        self.app.after_login()


NAV = [
    ("dash", "Painel"),
    ("scope", "Escopo"),
    ("scan", "Scan de site"),
    ("tools", "Ferramentas"),
    ("vault", "Cofre"),
    ("applock", "Bloqueio de apps"),
    ("panic", "Apagar / Backup"),
    ("notes", "Notas"),
    ("agents", "Agentes de IA"),
    ("vm", "Máquinas virtuais"),
    ("net", "Rede"),
    ("ai", "Modelo de IA"),
    ("maps", "Mapas"),
    ("remote", "Acesso remoto"),
    ("lab", "Laboratório"),
    ("audit", "Auditoria"),
]


class MainScreen(Screen):
    BINDINGS = [Binding("q", "quit_app", "Sair")]

    def __init__(self, client: Client):
        super().__init__()
        self.client = client
        self.current = "dash"

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Static("SENTINEL", classes="title")
                lv = ListView(*[ListItem(Label(label), id=f"nav-{key}") for key, label in NAV], id="nav")
                yield lv
            with VerticalScroll(id="content"):
                yield Static("Carregando...")

    def on_mount(self):
        self.show_panel("dash")

    @on(ListView.Selected, "#nav")
    def _nav(self, event: ListView.Selected):
        key = event.item.id.replace("nav-", "")
        self.show_panel(key)

    def action_quit_app(self):
        self.app.exit()

    def content(self) -> VerticalScroll:
        return self.query_one("#content", VerticalScroll)

    def show_panel(self, key):
        self.current = key
        box = self.content()
        box.remove_children()
        fn = getattr(self, f"panel_{key}", None)
        if fn:
            fn(box)
        else:
            box.mount(Static("Em construção."))

    def flash(self, msg, ok=True):
        self.app.notify(msg, severity="information" if ok else "error")

    def safe(self, fn, *a, **kw):
        try:
            return fn(*a, **kw)
        except ApiError as e:
            self.flash(str(e), ok=False)
            return None

    # ---------------- Painel ----------------
    def panel_dash(self, box):
        box.mount(Static("Painel", classes="title"))
        sysinfo = self.safe(self.client.system) or {}
        if sysinfo:
            gb = 1024 ** 3
            txt = (
                f"Host: {sysinfo.get('host')}   Usuário: {sysinfo.get('user')}\n"
                f"Sistema: {sysinfo.get('platform')}   Node: {sysinfo.get('node')}\n"
                f"CPU: {sysinfo.get('cpu')} ({sysinfo.get('cores')} núcleos)\n"
                f"Memória: {(sysinfo.get('memTotal', 0) - sysinfo.get('memFree', 0)) / gb:.1f} / {sysinfo.get('memTotal', 0) / gb:.1f} GB em uso\n"
                f"Uptime do servidor: {int(sysinfo.get('uptime', 0) // 3600)}h\n\n"
                f"Jobs ativos: {sysinfo.get('counts', {}).get('jobs', 0)}   "
                f"Alvos no escopo: {sysinfo.get('counts', {}).get('scope', 0)}   "
                f"Scans no histórico: {sysinfo.get('counts', {}).get('scans', 0)}"
            )
            box.mount(Static(txt, classes="card"))
        box.mount(Button("Atualizar", id="dash-refresh"))

    @on(Button.Pressed, "#dash-refresh")
    def _dash_refresh(self):
        self.show_panel("dash")

    # ---------------- Escopo ----------------
    def panel_scope(self, box):
        box.mount(Static("Escopo de alvos autorizados", classes="title"))
        box.mount(Static("Só alvos aqui podem ser varridos/atacados pelas ferramentas e agentes.", classes="hint"))
        data = self.safe(self.client.scope_list) or {"scope": []}
        table = DataTable(id="scope-table")
        table.add_columns("Alvo", "Nota")
        for item in data.get("scope", []):
            table.add_row(item.get("value", ""), item.get("note", ""))
        box.mount(table)
        row = Horizontal(
            Input(placeholder="dominio.com, IP ou CIDR", id="scope-value"),
            Input(placeholder="nota (opcional)", id="scope-note"),
            Button("Adicionar (confirmo que sou dono/autorizado)", id="scope-add", classes="-primary"),
        )
        box.mount(row)
        box.mount(Button("Remover selecionado", id="scope-remove", classes="-danger"))

    @on(Button.Pressed, "#scope-add")
    def _scope_add(self):
        value = self.query_one("#scope-value", Input).value.strip()
        note = self.query_one("#scope-note", Input).value.strip()
        if not value:
            return self.flash("Informe um alvo.", ok=False)
        if self.safe(self.client.scope_add, value, note, True) is not None:
            self.flash("Alvo adicionado.")
            self.show_panel("scope")

    @on(Button.Pressed, "#scope-remove")
    def _scope_remove(self):
        table = self.query_one("#scope-table", DataTable)
        if table.cursor_row is None:
            return self.flash("Selecione uma linha.", ok=False)
        value = table.get_row_at(table.cursor_row)[0]
        if self.safe(self.client.scope_remove, value) is not None:
            self.flash("Removido.")
            self.show_panel("scope")

    # ---------------- Scan ----------------
    def panel_scan(self, box):
        box.mount(Static("Scan de site", classes="title"))
        box.mount(Horizontal(
            Input(placeholder="https://alvo-autorizado.com", id="scan-target"),
            Select([("Rápido", "quick"), ("Padrão", "standard"), ("Profundo", "deep")], value="standard", id="scan-level"),
            Button("Escanear", id="scan-go", classes="-primary"),
        ))
        box.mount(RichLog(id="scan-log", wrap=True, highlight=False))
        box.mount(Static("Histórico", classes="title"))
        hist = self.safe(self.client.scan_history) or {"history": []}
        table = DataTable(id="scan-hist")
        table.add_columns("Alvo", "Nível", "Quando")
        for h in hist.get("history", [])[:30]:
            table.add_row(h.get("target", ""), h.get("level", ""), time.strftime("%d/%m %H:%M", time.localtime(h.get("startedAt", 0) / 1000)) if h.get("startedAt") else "")
        box.mount(table)

    @on(Button.Pressed, "#scan-go")
    def _scan_go(self):
        target = self.query_one("#scan-target", Input).value.strip()
        level = self.query_one("#scan-level", Select).value
        if not target:
            return self.flash("Informe o alvo.", ok=False)
        r = self.safe(self.client.scan_web, target, level)
        if r:
            self._watch_job(r["job"], self.query_one("#scan-log", RichLog))

    # ---------------- Ferramentas ----------------
    def panel_tools(self, box):
        box.mount(Static("Ferramentas externas", classes="title"))
        data = self.safe(self.client.tools_status) or {"tools": []}
        for t in data.get("tools", []):
            line = f"[b]{t['label']}[/b]  " + ("[green]instalado[/green]" if t["installed"] else "[red]não instalado[/red]")
            card = Vertical(
                Static(line),
                Static(t.get("desc", ""), classes="hint"),
                classes="card",
            )
            box.mount(card)
            if t["installed"]:
                row = Horizontal(
                    Input(placeholder="alvo (http://... ou host)", id=f"tool-target-{t['id']}"),
                    Button("Rodar", id=f"tool-run-{t['id']}", classes="-primary"),
                )
                box.mount(row)
            else:
                box.mount(Static(f"Instalar: {t['installHint']}", classes="hint"))
        box.mount(RichLog(id="tools-log", wrap=True, highlight=False))

    @on(Button.Pressed)
    def _tool_run_dispatch(self, event: Button.Pressed):
        bid = event.button.id or ""
        if bid.startswith("tool-run-"):
            tool = bid.replace("tool-run-", "")
            target = self.query_one(f"#tool-target-{tool}", Input).value.strip()
            if not target:
                return self.flash("Informe o alvo.", ok=False)
            r = self.safe(self.client.tools_run, tool, {"target": target, "preset": "quick"})
            if r:
                self._watch_job(r["job"], self.query_one("#tools-log", RichLog))

    def _watch_job(self, job_id, log_widget: RichLog):
        log_widget.clear()
        log_widget.write(f"[job {job_id}] iniciado...")
        self._poll_job(job_id, log_widget)

    @work(thread=True)
    def _poll_job(self, job_id, log_widget: RichLog):
        seen = 0
        while True:
            try:
                r = self.client.job_get(job_id)
            except ApiError as e:
                self.app.call_from_thread(log_widget.write, f"[erro] {e}")
                return
            status = r.get("status")
            self.app.call_from_thread(log_widget.write, f"status: {status}")
            if status != "running":
                break
            time.sleep(1.5)

    # ---------------- Cofre ----------------
    def panel_vault(self, box):
        box.mount(Static("Cofre", classes="title"))
        box.mount(Static("Gerador de senha", classes="title"))
        box.mount(Horizontal(Button("Gerar senha (256)", id="vault-genpw"), Button("Gerar frase-senha", id="vault-genphr")))
        box.mount(Static("", id="vault-out", classes="ok"))
        box.mount(Static("Criptografar / descriptografar arquivo", classes="title"))
        box.mount(Input(placeholder="/caminho/do/arquivo", id="vault-path"))
        box.mount(Input(placeholder="senha", password=True, id="vault-pw"))
        box.mount(Horizontal(
            Button("Criptografar", id="vault-enc", classes="-primary"),
            Button("Descriptografar", id="vault-dec"),
        ))

    @on(Button.Pressed, "#vault-genpw")
    def _vault_genpw(self):
        r = self.safe(self.client.vault_password, length=256)
        if r:
            pw = (r.get("passwords") or [""])[0]
            self.query_one("#vault-out", Static).update(pw)

    @on(Button.Pressed, "#vault-genphr")
    def _vault_genphr(self):
        r = self.safe(self.client.vault_passphrase, 6)
        if r:
            self.query_one("#vault-out", Static).update(r.get("passphrase", ""))

    @on(Button.Pressed, "#vault-enc")
    def _vault_enc(self):
        p = self.query_one("#vault-path", Input).value.strip()
        pw = self.query_one("#vault-pw", Input).value
        r = self.safe(self.client.vault_encrypt, p, pw, False)
        if r:
            self.flash(f"Criado: {r.get('output')}")

    @on(Button.Pressed, "#vault-dec")
    def _vault_dec(self):
        p = self.query_one("#vault-path", Input).value.strip()
        pw = self.query_one("#vault-pw", Input).value
        r = self.safe(self.client.vault_decrypt, p, pw)
        if r:
            self.flash(f"Restaurado: {r.get('output')}")

    # ---------------- Bloqueio de apps ----------------
    def panel_applock(self, box):
        box.mount(Static("Bloqueio de apps", classes="title"))
        s = self.safe(self.client.applock_state) or {"apps": [], "locked": True, "platform": "linux"}
        box.mount(Static(f"Estado: {'TRAVADO' if s.get('locked') else 'destravado'}  (plataforma: {s.get('platform')})", classes="ok" if not s.get("locked") else "danger"))
        table = DataTable(id="applock-table")
        table.add_columns("Processo")
        for a in s.get("apps", []):
            table.add_row(a.get("name", ""))
        box.mount(table)
        hint = "Nome do processo (ex.: discord)" if s.get("platform") != "win32" else "nome.exe"
        box.mount(Horizontal(Input(placeholder=hint, id="applock-in"), Button("Adicionar", id="applock-add", classes="-primary")))
        box.mount(Button("Remover selecionado", id="applock-remove", classes="-danger"))
        box.mount(Horizontal(
            Button("Travar agora", id="applock-lock"),
            Button("Destravar (pede PIN)", id="applock-unlock"),
        ))

    @on(Button.Pressed, "#applock-add")
    def _applock_add(self):
        v = self.query_one("#applock-in", Input).value.strip()
        if v and self.safe(self.client.applock_add, v) is not None:
            self.show_panel("applock")

    @on(Button.Pressed, "#applock-remove")
    def _applock_remove(self):
        table = self.query_one("#applock-table", DataTable)
        if table.cursor_row is None:
            return self.flash("Selecione uma linha.", ok=False)
        name = table.get_row_at(table.cursor_row)[0]
        if self.safe(self.client.applock_remove, name) is not None:
            self.show_panel("applock")

    @on(Button.Pressed, "#applock-lock")
    def _applock_lock(self):
        if self.safe(self.client.applock_lock) is not None:
            self.show_panel("applock")

    @on(Button.Pressed, "#applock-unlock")
    async def _applock_unlock(self):
        result = await self.app.push_screen_wait(PinModal("Destravar apps"))
        if not result:
            return
        if self.safe(self.client.applock_unlock, result["pin"]) is not None:
            self.show_panel("applock")

    # ---------------- Apagar / Backup ----------------
    def panel_panic(self, box):
        box.mount(Static("Apagar de emergência, backup e desinstalar", classes="title"))
        s = self.safe(self.client.panic_state) or {"targets": []}
        table = DataTable(id="panic-table")
        table.add_columns("Caminho", "Existe")
        for t in s.get("targets", []):
            table.add_row(t.get("path", ""), "sim" if t.get("exists") else "não")
        box.mount(table)
        box.mount(Horizontal(Input(placeholder="/caminho/a/apagar", id="panic-path"), Button("Adicionar alvo", id="panic-add")))
        box.mount(Horizontal(
            Button("Remover selecionado", id="panic-remove"),
            Button("Ver prévia", id="panic-preview"),
            Button("APAGAR agora", id="panic-exec", classes="-danger"),
        ))
        box.mount(Static("", id="panic-preview-out", classes="hint"))

        box.mount(Static("Sugestões (o que existe neste PC)", classes="title"))
        presets = self.safe(self.client.panic_presets) or []
        for p in presets[:12]:
            box.mount(Horizontal(Static(f"{p['group']}: {p['label']}", classes="hint"), Button("usar", id=f"panic-preset-{presets.index(p)}")))
        self._panic_presets = presets

        box.mount(Static("Backup explícito (você escolhe a pasta)", classes="title"))
        box.mount(Input(placeholder="/pasta/de/destino", id="backup-dest"))
        box.mount(Input(placeholder="senha do backup (8+ caracteres)", password=True, id="backup-pw"))
        box.mount(Button("Fazer backup", id="backup-go", classes="-primary"))

        box.mount(Static("Desinstalar o Sentinel (apaga o app inteiro)", classes="title danger"))
        box.mount(Static("Sem disfarce, sem gatilho oculto. Faça backup antes.", classes="hint"))
        box.mount(Button("Desinstalar o Sentinel", id="uninstall-go", classes="-danger"))

    @on(Button.Pressed)
    def _panic_preset_dispatch(self, event: Button.Pressed):
        bid = event.button.id or ""
        if bid.startswith("panic-preset-"):
            idx = int(bid.replace("panic-preset-", ""))
            p = self._panic_presets[idx]
            if self.safe(self.client.panic_target_add, p["path"], p["label"]) is not None:
                self.show_panel("panic")

    @on(Button.Pressed, "#panic-add")
    def _panic_add(self):
        p = self.query_one("#panic-path", Input).value.strip()
        if p and self.safe(self.client.panic_target_add, p, "") is not None:
            self.show_panel("panic")

    @on(Button.Pressed, "#panic-remove")
    def _panic_remove(self):
        table = self.query_one("#panic-table", DataTable)
        if table.cursor_row is None:
            return self.flash("Selecione uma linha.", ok=False)
        path = table.get_row_at(table.cursor_row)[0]
        if self.safe(self.client.panic_target_remove, path) is not None:
            self.show_panel("panic")

    @on(Button.Pressed, "#panic-preview")
    def _panic_preview(self):
        r = self.safe(self.client.panic_preview)
        if r:
            self.query_one("#panic-preview-out", Static).update(
                f"{r.get('totalFiles', 0)} arquivos, {r.get('totalBytes', 0) / 1024 / 1024:.1f} MB no total.")

    @on(Button.Pressed, "#panic-exec")
    async def _panic_exec(self):
        result = await self.app.push_screen_wait(PinModal("Apagar de emergência - irreversível", confirm_word="APAGAR", danger=True))
        if not result:
            return
        r = self.safe(self.client.panic_execute, result["pin"], result["word"])
        if r:
            self.flash(f"Apagado: {r.get('files', 0)} arquivos.")
            self.show_panel("panic")

    @on(Button.Pressed, "#backup-go")
    def _backup_go(self):
        dest = self.query_one("#backup-dest", Input).value.strip()
        pw = self.query_one("#backup-pw", Input).value
        r = self.safe(self.client.panic_backup, dest, pw)
        if r:
            self.flash(f"Backup criado: {r.get('file')}")

    @on(Button.Pressed, "#uninstall-go")
    async def _uninstall_go(self):
        result = await self.app.push_screen_wait(PinModal("Desinstalar o Sentinel - apaga tudo, para sempre", confirm_word="DESINSTALAR", danger=True))
        if not result:
            return
        r = self.safe(self.client.panic_selfdestruct, result["pin"], result["word"])
        if r:
            self.app.exit(message="Sentinel foi desinstalado.")

    # ---------------- Notas ----------------
    def panel_notes(self, box):
        box.mount(Static("Notas", classes="title"))
        data = self.safe(self.client.notes_list) or {"notes": []}
        for n in data.get("notes", []):
            card = Vertical(
                Static(n.get("title") or "(sem título)", classes="title"),
                Static(n.get("body", "")[:300]),
                Button("Apagar", id=f"note-del-{n['id']}", classes="-danger"),
                classes="card",
            )
            box.mount(card)
        box.mount(Static("Nova nota", classes="title"))
        box.mount(Input(placeholder="Título", id="note-title"))
        box.mount(Input(placeholder="Texto", id="note-body"))
        box.mount(Button("Salvar", id="note-save", classes="-primary"))

    @on(Button.Pressed)
    def _note_del_dispatch(self, event: Button.Pressed):
        bid = event.button.id or ""
        if bid.startswith("note-del-"):
            nid = bid.replace("note-del-", "")
            if self.safe(self.client.notes_remove, nid) is not None:
                self.show_panel("notes")

    @on(Button.Pressed, "#note-save")
    def _note_save(self):
        title = self.query_one("#note-title", Input).value.strip()
        body = self.query_one("#note-body", Input).value
        if self.safe(self.client.notes_upsert, None, title, body) is not None:
            self.show_panel("notes")

    # ---------------- Agentes ----------------
    def panel_agents(self, box):
        box.mount(Static("Agentes de IA", classes="title"))
        data = self.safe(self.client.agents_list) or {"agents": [], "sessions": []}
        opts = [(a["name"], a["id"]) for a in data.get("agents", [])]
        if opts:
            box.mount(Horizontal(
                Select(opts, id="agent-select"),
                Button("Nova conversa", id="agent-new", classes="-primary"),
            ))
        box.mount(RichLog(id="agent-log", wrap=True, highlight=False))
        box.mount(Horizontal(Input(placeholder="Mensagem para o agente...", id="agent-msg"), Button("Enviar", id="agent-send", classes="-primary")))
        box.mount(Horizontal(Static("", id="approval-bar")))

    @on(Button.Pressed, "#agent-new")
    def _agent_new(self):
        agent = self.query_one("#agent-select", Select).value
        r = self.safe(self.client.agents_session_new, agent)
        if r:
            self._session_id = r["id"]
            self.query_one("#agent-log", RichLog).clear()
            self._stop_stream = False
            self._stream_session(self._session_id)

    @work(thread=True)
    def _stream_session(self, sid):
        log = self.query_one("#agent-log", RichLog)

        def on_event(ev):
            k = ev.get("k")
            if k == "tok":
                return  # evita poluir o log token a token
            if k == "msg":
                self.app.call_from_thread(log.write, f"[{ev.get('role')}] {ev.get('text')}")
            elif k == "tool":
                self.app.call_from_thread(log.write, f"  > ferramenta: {ev.get('text')}")
            elif k == "result":
                self.app.call_from_thread(log.write, f"  < resultado: {ev.get('text')[:400]}")
            elif k == "approval":
                self.app.call_from_thread(self._show_approval, ev)
            elif k == "error":
                self.app.call_from_thread(log.write, f"[erro] {ev.get('text')}")
            elif k == "_error":
                self.app.call_from_thread(log.write, f"[conexão] {ev.get('text')}")

        self.client.stream(f"/api/agents/sessions/{sid}/stream", on_event, lambda: getattr(self, "_stop_stream", False))

    def _show_approval(self, ev):
        bar = self.query_one("#approval-bar", Static)
        bar.remove_children() if hasattr(bar, "remove_children") else None
        self._pending_approval = ev["id"]
        self.query_one("#agent-log", RichLog).write(f"[aprovação pendente] {ev.get('text')} -- use os botões abaixo")
        box = self.content()
        box.mount(Horizontal(
            Button("Aprovar", id="approve-yes", classes="-primary"),
            Button("Negar", id="approve-no", classes="-danger"),
        ))

    @on(Button.Pressed, "#approve-yes")
    def _approve_yes(self):
        if getattr(self, "_pending_approval", None):
            self.safe(self.client.agents_approve, self._pending_approval, True)
            self._pending_approval = None

    @on(Button.Pressed, "#approve-no")
    def _approve_no(self):
        if getattr(self, "_pending_approval", None):
            self.safe(self.client.agents_approve, self._pending_approval, False)
            self._pending_approval = None

    @on(Button.Pressed, "#agent-send")
    def _agent_send(self):
        sid = getattr(self, "_session_id", None)
        if not sid:
            return self.flash("Crie uma conversa primeiro.", ok=False)
        msg = self.query_one("#agent-msg", Input).value.strip()
        if not msg:
            return
        if self.safe(self.client.agents_session_send, sid, msg) is not None:
            self.query_one("#agent-msg", Input).value = ""

    # ---------------- VMs ----------------
    def panel_vm(self, box):
        box.mount(Static("Máquinas virtuais", classes="title"))
        prov = self.safe(self.client.vm_providers) or {}
        box.mount(Static(f"VirtualBox: {'sim' if prov.get('virtualbox') else 'não'}   Hyper-V: {'sim' if prov.get('hyperv') else 'não (ou N/A fora do Windows)'}", classes="hint"))
        data = self.safe(self.client.vm_list) or {"vms": []}
        table = DataTable(id="vm-table")
        table.add_columns("Provedor", "Nome", "Estado")
        for v in data.get("vms", []):
            table.add_row(v.get("provider", ""), v.get("name", ""), v.get("state", v.get("error", "")))
        box.mount(table)
        box.mount(Horizontal(
            Button("Iniciar", id="vm-start"), Button("Parar", id="vm-stop"),
            Button("Pausar", id="vm-pause"), Button("Snapshot", id="vm-snap"),
        ))

    @on(Button.Pressed)
    def _vm_action_dispatch(self, event: Button.Pressed):
        mapping = {"vm-start": "start", "vm-stop": "stop", "vm-pause": "pause", "vm-snap": "snapshot"}
        bid = event.button.id or ""
        if bid in mapping:
            table = self.query_one("#vm-table", DataTable)
            if table.cursor_row is None:
                return self.flash("Selecione uma VM.", ok=False)
            row = table.get_row_at(table.cursor_row)
            if self.safe(self.client.vm_action, row[0], row[1], mapping[bid]) is not None:
                self.flash("Feito.")
                self.show_panel("vm")

    # ---------------- Rede ----------------
    def panel_net(self, box):
        box.mount(Static("Rede", classes="title"))
        box.mount(Static("Geo-IP", classes="title"))
        box.mount(Horizontal(Input(placeholder="IP ou domínio (vazio = o seu)", id="net-geoip-q"), Button("Consultar", id="net-geoip-go")))
        box.mount(Static("", id="net-geoip-out", classes="hint"))
        box.mount(Static("E-mail temporário", classes="title"))
        box.mount(Button("Criar caixa temporária", id="net-tempmail-go", classes="-primary"))
        box.mount(Static("", id="net-tempmail-out", classes="ok"))
        box.mount(Static("Proxy do sistema", classes="title"))
        p = self.safe(self.client.proxy_system_get) or {}
        box.mount(Static("suportado neste SO" if p.get("supported") else "não suportado fora do Windows (configure o proxy do Linux no seu gerenciador de rede)", classes="hint"))

    @on(Button.Pressed, "#net-geoip-go")
    def _net_geoip(self):
        q = self.query_one("#net-geoip-q", Input).value.strip()
        r = self.safe(self.client.geoip, q or None)
        if r:
            self.query_one("#net-geoip-out", Static).update(json.dumps(r, ensure_ascii=False, indent=2))

    @on(Button.Pressed, "#net-tempmail-go")
    def _net_tempmail(self):
        r = self.safe(self.client.tempmail_create)
        if r:
            self.query_one("#net-tempmail-out", Static).update(str(r.get("address", r)))

    # ---------------- IA ----------------
    def panel_ai(self, box):
        box.mount(Static("Modelo de IA (Ollama local)", classes="title"))
        r = self.safe(self.client.ai_status) or {}
        ollama = r.get("ollama", {})
        settings = r.get("settings", {})
        box.mount(Static(f"Ollama: {'rodando' if ollama.get('running') else 'parado'}   Modelo atual: {settings.get('ollamaModel', '?')}", classes="ok" if ollama.get("running") else "danger"))
        models = ollama.get("models", [])
        if models:
            table = DataTable(id="ai-models")
            table.add_columns("Modelo", "Tamanho")
            for m in models:
                size = m.get("size", 0)
                table.add_row(m.get("name", ""), f"{size / 1024 / 1024 / 1024:.1f} GB" if size else "")
            box.mount(table)
        box.mount(Horizontal(Button("Iniciar Ollama", id="ai-serve"), Input(placeholder="modelo a baixar (ex.: qwen2.5-coder:7b)", id="ai-pull-name"), Button("Baixar", id="ai-pull-go")))

    @on(Button.Pressed, "#ai-serve")
    def _ai_serve(self):
        if self.safe(self.client.ai_serve) is not None:
            self.flash("Pedido enviado.")

    @on(Button.Pressed, "#ai-pull-go")
    def _ai_pull(self):
        name = self.query_one("#ai-pull-name", Input).value.strip()
        if name and self.safe(self.client.ai_pull, name) is not None:
            self.flash("Download iniciado (acompanhe pelos Jobs).")

    # ---------------- Mapas ----------------
    def panel_maps(self, box):
        box.mount(Static("Mapas", classes="title"))
        box.mount(Static(
            f"Satélite, aviação e clima são visuais (Leaflet) - abra no navegador: {BASE_URL}/\n"
            "Aqui no terminal mostramos só o mapa de ameaças, que é puro dado (lista de IPs).",
            classes="hint"))
        r = self.safe(self.client.maps_threats) or {"state": None, "legend": {}}
        points = (r.get("state") or {}).get("points", []) or []
        table = DataTable(id="threats-table")
        table.add_columns("IP", "País", "Cidade", "Pontuação")
        for it in points[:60]:
            table.add_row(it.get("ip", ""), it.get("country", ""), it.get("city", ""), str(it.get("score", "")))
        box.mount(table)
        box.mount(Button("Atualizar lista de ameaças", id="threats-refresh"))

    @on(Button.Pressed, "#threats-refresh")
    def _threats_refresh(self):
        if self.safe(self.client.maps_threats_refresh) is not None:
            self.flash("Atualização pedida, pode levar um tempo.")

    # ---------------- Acesso remoto ----------------
    def panel_remote(self, box):
        box.mount(Static("Acesso remoto", classes="title"))
        r = self.safe(self.client.remote_get) or {}
        cfg = r.get("config", {})
        box.mount(Static(f"Status: {'ligado' if cfg.get('enabled') else 'desligado'}   Porta: {r.get('port')}", classes="ok" if cfg.get("enabled") else "hint"))
        ifaces = r.get("interfaces", [])
        if ifaces:
            table = DataTable(id="remote-ifaces")
            table.add_columns("Interface", "IP")
            for i in ifaces:
                table.add_row(i.get("name", ""), i.get("ip", ""))
            box.mount(table)
        box.mount(Horizontal(
            Button("Ligar na primeira interface listada", id="remote-on", classes="-primary"),
            Button("Desligar", id="remote-off"),
        ))
        self._ifaces = ifaces

    @on(Button.Pressed, "#remote-on")
    def _remote_on(self):
        if not getattr(self, "_ifaces", None):
            return self.flash("Nenhuma interface de rede privada detectada.", ok=False)
        ip = self._ifaces[0]["ip"]
        if self.safe(self.client.remote_set, enabled=True, bindIp=ip) is not None:
            self.show_panel("remote")

    @on(Button.Pressed, "#remote-off")
    def _remote_off(self):
        if self.safe(self.client.remote_set, enabled=False) is not None:
            self.show_panel("remote")

    # ---------------- Laboratório ----------------
    def panel_lab(self, box):
        box.mount(Static("Laboratório (CyberLab)", classes="title"))
        s = self.safe(self.client.lab_state) or {}
        box.mount(Static(json.dumps(s, ensure_ascii=False, indent=2), classes="hint"))
        box.mount(Horizontal(Button("Ligar", id="lab-start", classes="-primary"), Button("Desligar", id="lab-stop")))

    @on(Button.Pressed, "#lab-start")
    def _lab_start(self):
        if self.safe(self.client.lab_start) is not None:
            self.flash("Laboratório iniciado.")

    @on(Button.Pressed, "#lab-stop")
    def _lab_stop(self):
        if self.safe(self.client.lab_stop) is not None:
            self.flash("Laboratório parado.")

    # ---------------- Auditoria ----------------
    def panel_audit(self, box):
        box.mount(Static("Auditoria", classes="title"))
        data = self.safe(self.client.audit) or {"events": []}
        table = DataTable(id="audit-table")
        table.add_columns("Quando", "Evento", "Detalhe")
        for e in data.get("events", [])[:200]:
            when = str(e.get("t", ""))[:19].replace("T", " ")
            detail = {k: v for k, v in e.items() if k not in ("t", "type", "actor")}
            table.add_row(when, e.get("type", ""), json.dumps(detail, ensure_ascii=False)[:80])
        box.mount(table)


class SentinelApp(App):
    CSS = CSS
    TITLE = "Sentinel"

    def __init__(self):
        super().__init__()
        self.client = Client(BASE_URL)

    def on_mount(self):
        try:
            state = self.client.auth_state()
        except ApiError as e:
            self.exit(message=f"Não consegui falar com o Sentinel em {BASE_URL}\n{e}\n\nO backend está rodando? (node server.js)")
            return
        if not state.get("setup") or not state.get("authed"):
            self.push_screen(LoginScreen(self.client, state))
        else:
            self.after_login()

    def after_login(self):
        # troca a tela de login/setup pela principal
        while len(self.screen_stack) > 1:
            self.pop_screen()
        self.push_screen(MainScreen(self.client))


if __name__ == "__main__":
    SentinelApp().run()
