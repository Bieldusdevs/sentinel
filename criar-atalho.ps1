# Cria um atalho "Sentinel" na area de trabalho.
# Prefere o app nativo (Sentinel.exe); se nao existir, cai para o iniciar.bat (Node + janela do Edge).
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $dir 'Sentinel.exe'
$lnk = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Sentinel.lnk'
$s = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
if (Test-Path $exe) {
  $s.TargetPath = $exe
  $s.WindowStyle = 1
} else {
  $s.TargetPath = Join-Path $dir 'iniciar.bat'
  $s.WindowStyle = 7  # minimizado: so a janela do app aparece
}
$s.WorkingDirectory = $dir
$s.Description = 'Sentinel - workbench local de ciberseguranca'
$s.Save()
Write-Host "Atalho criado: $lnk  ->  $($s.TargetPath)"
