param(
    [int]$MaxOutput = -1
)
$dir = $PSScriptRoot
$csv = Join-Path $dir "result.csv"
$txt = Join-Path $dir "cloudflare_ips.txt"

if (-not (Test-Path $csv)) {
    exit 1
}

# 机场三字码到中文国家/地区的映射对照表
$countryMap = @{
    "HKG" = "中国香港"
    "MFM" = "中国澳门"
    "TPE" = "中国台湾"
    "KHH" = "中国台湾"
    "SIN" = "新加坡"
    "NRT" = "日本"
    "KIX" = "日本"
    "ITM" = "日本"
    "FUK" = "日本"
    "ICN" = "韩国"
    "BKK" = "泰国"
    "KUL" = "马来西亚"
    "SGN" = "越南"
    "HAN" = "越南"
    "MNL" = "菲律宾"
    "CGK" = "印度尼西亚"
    "LAX" = "美国"
    "SJC" = "美国"
    "SFO" = "美国"
    "SEA" = "美国"
    "ORD" = "美国"
    "DFW" = "美国"
    "EWR" = "美国"
    "IAD" = "美国"
    "ATL" = "美国"
    "MIA" = "美国"
    "DEN" = "美国"
    "PHX" = "美国"
    "PDX" = "美国"
    "SAN" = "美国"
    "BOS" = "美国"
    "DTW" = "美国"
    "MSP" = "美国"
    "YYZ" = "加拿大"
    "YVR" = "加拿大"
    "YUL" = "加拿大"
    "LHR" = "英国"
    "FRA" = "德国"
    "CDG" = "法国"
    "AMS" = "荷兰"
    "MAD" = "西班牙"
    "BCN" = "西班牙"
    "MXP" = "意大利"
    "FCO" = "意大利"
    "WAW" = "波兰"
    "ARN" = "瑞典"
    "SYD" = "澳大利亚"
    "MEL" = "澳大利亚"
    "BNE" = "澳大利亚"
    "PER" = "澳大利亚"
    "AKL" = "新西兰"
    "DXB" = "阿联酋"
    "GRU" = "巴西"
}

$lines = Get-Content $csv | Select-Object -Skip 1
$parsed = $lines | ForEach-Object {
    $f = $_ -split ','
    if ($f.Count -ge 8) {
        $code = $f[6].Trim().ToUpper()
        $country = if ($countryMap.ContainsKey($code)) { $countryMap[$code] } else { $code }
        '{0}:{1}#{2}-{3}MB/s' -f $f[0].Trim(), $f[7].Trim(), $country, $f[5].Trim()
    }
}

if ($MaxOutput -gt 0) {
    $parsed = $parsed | Select-Object -First $MaxOutput
}

$parsed | Set-Content -Encoding UTF8 $txt