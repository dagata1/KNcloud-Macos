$ErrorActionPreference = 'Stop'

# Build the lwIP/TAP tun2socks engine used by SSTap.
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$thirdParty = Join-Path $root 'third_party'
$source = Join-Path $thirdParty 'badvpn'
$build = Join-Path $thirdParty 'badvpn-build-zig2'
$install = Join-Path $root 'cores\native'
$cmake = if ($env:CMAKE) { $env:CMAKE } else { 'cmake' }
$ninja = if ($env:NINJA) { $env:NINJA } else { 'ninja' }
$cc = if ($env:CC) { $env:CC } else { 'zig cc' }

New-Item -ItemType Directory -Force -Path $thirdParty | Out-Null
if (!(Test-Path (Join-Path $source 'CMakeLists.txt'))) {
    git clone --depth 1 https://github.com/ambrop72/badvpn.git $source
}

New-Item -ItemType Directory -Force -Path $build | Out-Null
# Ninja keeps the build independent of a full Visual Studio installation.
$ccParts = $cc -split ' ' | Where-Object { $_ -ne '' }
$ccArg1 = if ($ccParts.Count -gt 1) { $ccParts[1] } else { '' }
$zigPath = $ccParts[0]
$toolBin = Join-Path $build 'tool-bin'
New-Item -ItemType Directory -Force -Path $toolBin | Out-Null
$archiveSource = Join-Path (Join-Path $root 'tools') 'native-archive-wrapper.go'
$go = (Get-Command go -ErrorAction Stop).Source
$env:ZIG = $zigPath
& $go build -o (Join-Path $toolBin 'ar.exe') $archiveSource
if ($LASTEXITCODE -ne 0) { throw 'failed to build archive wrapper' }
Copy-Item (Join-Path $toolBin 'ar.exe') (Join-Path $toolBin 'ranlib.exe') -Force
$env:Path = $toolBin + ';' + $env:Path
& $cmake -S $source -B $build -G Ninja "-DCMAKE_MAKE_PROGRAM:FILEPATH=$ninja" `
    "-DCMAKE_C_COMPILER=$($ccParts[0])" "-DCMAKE_C_COMPILER_ARG1=$ccArg1" `
    -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_TUN2SOCKS=1 `
    "-DCMAKE_INSTALL_PREFIX=$install"
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed" }
& $cmake --build $build --config Release --target install
if ($LASTEXITCODE -ne 0) { throw "native tun2socks build failed" }

$binary = Join-Path $install 'bin\badvpn-tun2socks.exe'
if (!(Test-Path $binary)) {
    throw "native tun2socks was not produced: $binary"
}
Write-Output $binary