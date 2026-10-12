# SPDX-License-Identifier: AGPL-3.0-only
param([switch]$SkipBuild)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$metadata=& cargo metadata --no-deps --format-version 1 | ConvertFrom-Json
if(-not $SkipBuild){
    & cargo build -p luqnexa-server --locked
    if($LASTEXITCODE){throw 'server build failed'}
    & cargo build --manifest-path (Join-Path $root 'modules/Luqnexa/Cargo.toml') --target-dir $metadata.target_directory -p nextime-cli --locked
    if($LASTEXITCODE){throw 'CLI build failed'}
}
$metadata=& cargo metadata --no-deps --format-version 1 | ConvertFrom-Json
$server=Join-Path $metadata.target_directory 'debug/luqnexa-server.exe'
$cli=Join-Path $metadata.target_directory 'debug/nextime.exe'
$run=Join-Path $root ('.cache/phase45/'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $run | Out-Null
$base=Join-Path $run 'base.tsv';$next=Join-Path $run 'next.tsv'
"し`t詩`tnoun`t100`nはし`t橋`tnoun`t100" | Set-Content -LiteralPath $base -Encoding utf8
"し`t詩`tnoun`t100`nはし`t橋`tnoun`t100`nはし`t箸`tnoun`t120" | Set-Content -LiteralPath $next -Encoding utf8
function Run-Service([string[]]$Arguments){& $server @Arguments; if($LASTEXITCODE){throw ('service command failed: '+$Arguments[0])}}
function Start-Release([string]$Release,[string]$PublicKey){
    $log=Join-Path $run ([guid]::NewGuid().ToString('N')+'.log');$errorLog=$log+'.error'
    $process=Start-Process -FilePath $server -ArgumentList @('serve',('"'+$Release+'"'),('"'+$PublicKey+'"'),'127.0.0.1:0') -WindowStyle Hidden -RedirectStandardOutput $log -RedirectStandardError $errorLog -PassThru
    $script:ownedProcesses+=@($process)
    $deadline=(Get-Date).AddSeconds(20)
    while((Get-Date)-lt $deadline){if($process.HasExited){throw 'server exited'};if(Test-Path -LiteralPath $log){$address=(Get-Content -LiteralPath $log -ErrorAction SilentlyContinue | Select-Object -First 1);if($address -match '^http://127\.0\.0\.1:\d+$'){return $address}};Start-Sleep -Milliseconds 100}
    throw 'server readiness timeout'
}
$ownedProcesses=@();$oldSigning=$env:LUQNEXA_SIGNING_KEY_FILE;$oldToken=$env:LUQNEXA_SUBMISSION_TOKEN
try{
    $keys=Join-Path $run 'keys';Run-Service @('keygen',$keys)
    $public=Join-Path $keys 'public.key';$env:LUQNEXA_SIGNING_KEY_FILE=Join-Path $keys 'signing.key'
    $env:LUQNEXA_SUBMISSION_TOKEN=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $a=Join-Path $run 'a.nud';$b=Join-Path $run 'b.nud'
    & $cli dict build $base $a 1;if($LASTEXITCODE){throw 'base build failed'}
    & $cli dict build $next $b 2;if($LASTEXITCODE){throw 'next build failed'}
    $first=Join-Path $run 'release1';$second=Join-Path $run 'release2'
    Run-Service @('publish',$a,$first,'1');Run-Service @('publish',$b,$second,'2',$a)
    $url=Start-Release $first $public
    $manifest=Join-Path $run 'download-manifest.json';$artifact=Join-Path $run 'download.nud'
    Invoke-WebRequest "$url/api/v1/manifest" -OutFile $manifest
    Invoke-WebRequest "$url/api/v1/artifact" -OutFile $artifact
    $store=Join-Path $run 'isolated-store';Run-Service @('install',$store,$public,$manifest,$artifact,'full')
    $word=@{reading='し';surface='詩';language='ja';source_url='https://example.org/public';license='AGPL-3.0-only';share_consent=$true}|ConvertTo-Json -Compress
    $accepted=Invoke-RestMethod "$url/api/v1/words/submit" -Method Post -Headers @{Authorization=('Bearer '+$env:LUQNEXA_SUBMISSION_TOKEN)} -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($word))
    if($accepted.status -ne 'pending-human-review'){throw 'word not held for review'}
    $nextUrl=Start-Release $second $public
    $sha=(Get-Content -LiteralPath $manifest -Raw|ConvertFrom-Json).manifest.sha256
    $update=Invoke-RestMethod "$nextUrl/api/v1/updates?from=$sha"
    if($update.kind -ne 'delta'){throw 'delta not selected'}
    $nextManifest=Join-Path $run 'next-manifest.json';$patch=Join-Path $run 'download-delta.json'
    Invoke-WebRequest "$nextUrl/api/v1/manifest" -OutFile $nextManifest
    Invoke-WebRequest "$nextUrl/api/v1/delta" -OutFile $patch
    Run-Service @('install',$store,$public,$nextManifest,$patch,'delta')
    $pointer=Get-Content -LiteralPath (Join-Path $store 'current.json') -Raw|ConvertFrom-Json
    if($pointer.current -ne 2){throw 'delta did not activate version 2'}
    Run-Service @('rollback',$store,$public)
    $pointer=Get-Content -LiteralPath (Join-Path $store 'current.json') -Raw|ConvertFrom-Json
    if($pointer.current -ne 1 -or $pointer.highest -ne 2){throw 'rollback broke high-water mark'}
    Run-Service @('assist','先生','明日','体調不良')
    Run-Service @('memory-demo',(Join-Path $run 'private-memory-demo'))
    $result=@{passed=$true;dictionary_full=$true;dictionary_delta=$true;rollback=$true;review_queue=$true;offline_drafts=$true;encrypted_memory=$true;ime_installed=$false;run=$run}
    $result|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $run 'report.json') -Encoding utf8
    $result|ConvertTo-Json
}finally{
    foreach($process in $ownedProcesses){if(-not $process.HasExited){Stop-Process -Id $process.Id -ErrorAction SilentlyContinue}}
    $env:LUQNEXA_SIGNING_KEY_FILE=$oldSigning;$env:LUQNEXA_SUBMISSION_TOKEN=$oldToken
}
