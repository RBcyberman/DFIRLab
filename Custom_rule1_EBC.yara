rule malware_EBC_Siuchung
{
       meta: 
              description = "Detects malware with file name EBC"
              author = "Siu Chung Lo"
       strings:
              $s1 = "75C8FD04AD916AEC3E3D5CB76A452B116B3D4D0912A0A485E9FB8E3D240E210C" ascii wide
              $s2 = "6KOT$GA" ascii wide 
              $s3 = "Lzp[Wm5o9c" ascii wide 
              $s4 = "PublicKeyToken=b77a5c561934e089" ascii wide 
       condition: 
              3 of them 
}
