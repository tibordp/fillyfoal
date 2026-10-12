# NT Kernel Logger with PROCESS|THREAD|NO_SYSCONFIG (0x10000003) for 0.5 s, recorded once the
# box was quiet (only the fillyfoal session logged on). Run elevated (elevate.ps1).
# The process rundown carries the full command line of every running process, so the result
# must be reviewed by hand (tracerpt dump) before publishing.
$work = 'C:\fillyfoal\winfix\work\etl'
$out  = 'C:\fillyfoal\winfix\out\etl'
$f = "$work\kernel-logger-procthread-raw.etl"
Remove-Item $f -ErrorAction SilentlyContinue
& "$work\ff_klog.exe" kernel $f 10000003 500
Start-Process cmd -ArgumentList '/c','echo fillyfoal test' -Wait -WindowStyle Hidden
tracerpt $f -o "$work\kproc.xml" -of XML -summary "$work\kproc.summary.txt" -y | Out-Null
