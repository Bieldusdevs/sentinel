# Sentinel

Workbench local de cibersegurança com agentes de IA, ferramentas de teste, cofre de arquivos, mapas e acesso remoto privado.
Tema monocromático (preto e branco) com estética de terminal. Backend em Node.js (zero dependências): no Windows um app nativo em C++ (janela própria, sem a barra padrão do Windows); no Linux uma TUI em Python (Textual), tudo no terminal.

## Como iniciar

```bash
git clone <url-deste-repositório>
cd <pasta-clonada>
```

**Linux — clona e já roda (app de terminal):**
```bash
./linux/start.sh
```
Sobe o mesmo backend (`node server.js`, sem nenhuma mudança de comportamento) e abre uma interface bonita de terminal em Python (biblioteca [Textual](https://textual.textualize.io/)), que fala com o backend pela mesma API REST que a web usa. Na primeira vez, cria sozinho um ambiente Python isolado (`linux/.venv`) e instala as duas dependências (`textual`, `requests`). Fechar a TUI (`q` ou Ctrl+C) encerra o backend junto, igual o `Sentinel.exe` no Windows.
- Precisa de `node` e `python3` instalados (`sudo apt install nodejs python3 python3-venv` no Debian/Ubuntu).
- A interface web continua disponível ao mesmo tempo em `http://127.0.0.1:7777` num navegador, se preferir - o launcher mostra o endereço.
- Os mapas (Satélite/Aviação/Clima) são visuais (Leaflet): a TUI mostra o mapa de Ameaças como tabela (é só dado) e aponta pro navegador para os outros três.
- `linux/sentinel.desktop` é um atalho opcional de menu (copie para `~/.local/share/applications/`).

**Windows — app nativo (janela própria, sem cara de navegador):**
```bash
app\build.bat         # compila o Sentinel.exe (precisa do Visual Studio Build Tools 2022 com C++)
Sentinel.exe
```
O `Sentinel.exe` sobe o backend sozinho, mostra a interface numa janela nativa (WebView2) e encerra o backend ao fechar. `criar-atalho.ps1` cria um atalho no desktop; `instalar-inicio-automatico.ps1` (opcional) inicia ao entrar no Windows.
O SDK do WebView2 (`app/webview2/`) não vai no Git (é grande e redistribuível) - baixe o pacote NuGet `Microsoft.Web.WebView2` e copie as pastas `include/` e `lib/` (x64) para dentro de `app/webview2/` antes de compilar. Sem isso, dá pra rodar igual pelo `node server.js --open` ou pelo app Linux.

**Sem o executável, em qualquer sistema (Node direto):**
```bash
node server.js --open
```

- Abre em `http://127.0.0.1:7777`.
- Primeiro acesso: crie um PIN e **anote o número de recuperação** (aparece uma única vez - sem ele, se esquecer o PIN, não tem como recuperar o acesso).
- Os dados (config, auditoria, cache) ficam em `data/`, criada sozinha no primeiro uso e fora do Git.

## O que tem

| Área | O que faz |
|---|---|
| **Agentes** | 6 perfis especializados (Dev, Admin do PC, Red Team, Blue Team, Operador de VMs, Tutor), cada um com metodologia própria, ferramentas próprias e autonomia ajustável |
| **Modelos de IA** | 100% local e gratuita com Ollama: 7B (rápido, cabe na GPU) ou 14B (mais capaz, mais lento); baixa e troca de modelo pela interface |
| **Website Scan** | Quick / Standard / Deep: cabeçalhos, cookies, TLS, tecnologias, PHP EOL, descoberta ativa de caminhos |
| **Ferramentas** | Port scan TCP embutido + nmap, Nikto, Metasploit, sqlmap, WhatWeb, Gobuster (detecta o que está instalado) |
| **Escopo** | Lista de alvos autorizados. Tudo que é ofensivo recusa alvos fora dela |
| **Laboratório** | Liga/desliga o CyberLab (`../cyber-lab`) e gerencia VMs (VirtualBox; Hyper-V se houver) |
| **Cofre** | Gerador de senhas (padrão 256 caracteres), criptografia de arquivos/pastas (AES-256-GCM + scrypt) e bloqueio de apps |
| **Apagar de emergência** | Apaga, com PIN, uma lista de pastas/arquivos que você escolhe (cache e histórico de navegadores, Discord, VS Code, itens recentes etc.). Nunca apaga o Windows, programas instalados ou o perfil inteiro. Também tem backup cifrado explícito e "Desinstalar o Sentinel" (apaga o app inteiro, de si mesmo, sem disfarce) |
| **Notas** | Anotações rápidas, salvas no servidor (acessíveis também pelo acesso remoto) |
| **Mapas** | Satélite (Esri), tráfego aéreo ao vivo (OpenSky), radar de chuva (RainViewer) e IPs reportados atacando nas últimas 48h (blocklist.de, geolocalizado) — tudo gratuito, sem chave de API |
| **Rede** | Geo-IP, e-mail temporário (mail.tm), proxy do Windows + teste de proxies |
| **QR Code** | Texto/URL, Wi-Fi, e-mail, telefone; baixa SVG/PNG |
| **Aprender** | 14 aulas (7 de Linux, 7 de cibersegurança) com comandos, exercícios no lab e quiz |
| **Acesso remoto** | Pela sua VPN privada (Tailscale recomendado), com PIN + 2FA |

## Segurança: o que foi decidido e por quê

- **Aprovação dos agentes.** Três níveis por agente: *Perguntar* (só leitura é automática), *Seguro* (leitura e scans do escopo automáticos; escrita, shell e VMs pedem OK) e *Total* (nada pede OK; ligar exige o PIN). Mesmo no modo Total continuam valendo o escopo de alvos e uma lista de bloqueios catastróficos (formatar disco, apagar o sistema, mexer na pasta `data`). Conteúdo lido de páginas e arquivos é tratado como dado, mas **prompt injection é um risco real**: não deixe o modo Total ligado em agentes que leem a web.
- **Sem IP público.** O servidor escuta em `127.0.0.1` e, se você ligar o acesso remoto, só em endereço privado/VPN (Tailscale `100.64/10`, LAN). Nada de abrir porta no roteador.
- **Defesas do servidor:** login com scrypt, rate limit, 2FA TOTP opcional, cookie HttpOnly/SameSite, validação do header `Host` (anti DNS-rebinding), cabeçalho anti-CSRF e CSP restrita.
- **Banco de dados local:** tudo (config, PIN, escopo, notas, auditoria) fica em `data/sentinel.db`, um banco SQLite de verdade (via [`node:sqlite`](https://nodejs.org/api/sqlite.html), nativo do Node 22.5+ - sem instalar nada a mais, continua "zero dependências"). Nada sai dessa pasta, nada vai pra nuvem. Se o projeto já rodou antes no formato antigo (`config.json` + `audit.log`), o próprio `server.js` migra os dados pro banco sozinho na primeira vez que sobe e renomeia os arquivos antigos para `.migrated` (nada é apagado). Testado de verdade aqui: PIN + recuperação, escopo, notas e auditoria passando pelo banco novo via API, e a migração a partir de um `config.json`/`audit.log` de exemplo (dados antigos preservados 1:1).
- **Auditoria:** tudo que agentes e você fizeram fica gravado no banco (tabela `audit`, visível na aba Segurança).
- **Escopo:** adicionar um alvo exige declarar que você é dono ou tem autorização. Testar sistemas de terceiros sem permissão é crime.
- **Backup e desinstalar, não backdoor.** "Apagar de emergência" tem backup explícito (você escolhe a pasta de destino, sem envio automático escondido) e "Desinstalar o Sentinel" (apaga o app inteiro de si mesmo, com PIN + confirmação). Nenhum dos dois se disfarça de outro programa nem tem gatilho oculto — são botões visíveis que só você aciona. Desinstalar dispara pelo Agendador de Tarefas do Windows (a única forma confiável de um processo sobreviver ao pai que o criou e ainda assim terminar o trabalho) e se limpa sozinho depois.
- **Mapa de ameaças:** mostra IPs *já reportados* atacando (SSH, e-mail, web) nas últimas ~48h via blocklist.de — não é um feed de "ataque ao vivo" como os mapas decorativos de grandes fabricantes (que rodam em telemetria privada). É dado real, só que histórico recente, não instantâneo.

## Limites e avisos honestos

- **Linux: testado de verdade, mas não numa máquina Linux.** O desenvolvimento inteiro foi feito num Windows. O backend (`lib/panic.js`, `tools.js`, `vm.js`, `applock.js`, `agents.js`) tem ramos próprios para Linux (caminhos protegidos, detecção de ferramentas no PATH, bloqueio de apps via `/proc`, autodestruição via `setsid` em vez do Agendador de Tarefas do Windows, shell do agente via `/bin/sh`) e as validações de segurança desses ramos foram testadas de verdade (com `process.platform` forçado para `'linux'` e checagens de regex/caminho uma a uma - todas passaram). A TUI em Python foi testada de ponta a ponta contra o backend real rodando aqui (login, navegação, dados reais aparecendo nas telas). O que **não** foi testado: os comandos de shell específicos do Linux (`setsid`, `/proc/<pid>/comm` etc.) rodando de fato num kernel Linux, e detecção real do VirtualBox/nmap/nikto instalados via APT. Se algo não funcionar na sua distro, é provável que seja nesses pontos - avise.
- **IA local (medido neste PC):** `qwen2.5-coder:7b` gera ~10 tok/s e um agente resolve tarefas simples em 10-30 s; `qwen2.5-coder:14b` gera ~3 tok/s (35 s só para carregar) e tarefas levam minutos, em troca de erros menores. Acima de 14B não cabe. Baixe e troque o modelo em *Modelos de IA* (4,7 a 9,3 GB; o disco tem pouco espaço livre). Modelos pequenos erram contagens e podem inventar saídas: por isso o sistema corta a geração ao fim de cada chamada de ferramenta e já entrega totais prontos.
- **Bloqueio de apps:** só funciona com o Sentinel rodando e só barra a *abertura* de apps (processos iniciados depois do bloqueio). Não é um serviço do Windows.
- **Criptografia de arquivos:** sem a senha não há recuperação. O número de recuperação do PIN só redefine o acesso ao Sentinel, não decifra arquivos.
- **Hyper-V** exige PowerShell como administrador; VirtualBox funciona sem.
- **WSL** neste PC está com defeito (classe não registrada), então Kali/Nikto via WSL não são detectados. Há uma VM Kali no VirtualBox que aparece em *Laboratório*.
- A senha de 256 caracteres é um segredo de máquina (tokens, proxies, chaves): guarde em um gerenciador de senhas, não para digitar.

## Acesso de fora de casa (resumo)

1. Instale o Tailscale no PC (`winget install -e --id Tailscale.Tailscale`) e no celular, na mesma conta.
2. Em **Acesso remoto**, escolha a interface Tailscale e ligue.
3. Ative o **2FA** em Segurança.
4. No celular, abra o endereço `100.x.x.x:7777` mostrado (ou escaneie o QR). Mantenha o PC ligado e sem suspensão.

## Estrutura

```
server.js            servidor HTTP + rotas + listeners
lib/                 auth, escopo, jobs, scanner, tools, vault, panic, applock, vm, netutil, ai, agents, remote, notes, maps
public/              interface (core.js, p-*.js, lessons.js, app.css) + fontes Geist, ícones Lucide e Leaflet locais
app/                 app nativo C++ (sentinel.cpp, build.bat, app.manifest) + SDK WebView2 (Windows)
linux/               app de terminal em Python (sentinel_tui.py), start.sh, requirements.txt, sentinel.desktop
Sentinel.exe         app nativo compilado (janela própria; sobe e encerra o backend)
data/                sentinel.db (SQLite: config, PIN, escopo, notas, auditoria) + cache; criado no primeiro uso, fora do Git
```

Variáveis úteis: `SENTINEL_PORT` (padrão 7777), `SENTINEL_DATA` (pasta de dados), `CYBERLAB_DIR`.
