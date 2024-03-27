rule malware_CXY_Siuchung
{
       meta: 
              description = "Detects malware with file name CXY"
              author = "Siu Chung Lo"
       strings:
              $s1 = "CRT$XIZ" ascii wide
              $s2 = "efkrm4tgkl4ytg4" ascii wide 
       condition: 
              $s1 and $s2 
}
