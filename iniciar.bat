@echo off
rem Inicia o Sentinel e abre a janela do app (Edge em modo aplicativo).
cd /d "%~dp0"
where node >nul 2>nul || (echo Node.js nao encontrado. Instale em https://nodejs.org & pause & exit /b 1)
title Sentinel
node server.js --open
