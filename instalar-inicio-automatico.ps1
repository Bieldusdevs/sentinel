# OPCIONAL: inicia o Sentinel (sem abrir janela) quando voce entrar no Windows, para o acesso remoto
# funcionar mesmo se voce esquecer de abrir o app. Cria UMA tarefa agendada do usuario atual.
# Para remover:  Unregister-ScheduledTask -TaskName Sentinel -Confirm:$false
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$node = (Get-Command node -ErrorAction Stop).Source
$action = New-ScheduledTaskAction -Execute $node -Argument 'server.js' -WorkingDirectory $dir
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName 'Sentinel' -Action $action -Trigger $trigger -Settings $settings -Description 'Sentinel (servidor local)' | Out-Null
Write-Host 'Tarefa "Sentinel" criada. Ela inicia no proximo logon.'
