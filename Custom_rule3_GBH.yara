rule malware_GBH_Siuchung
{
       meta: 
              description = "Detects malware with file name GBH"
              author = "Siu Chung Lo"
       strings:
              $s1 = "<htr<jtb<lt6<tt&<wt" ascii wide
              $s2 = "WATAUAVAWH" ascii wide 
              $s3 = "XttBWCoRwPJzgAlgrJMMMgGxjpHmjGilKkTeuwtnqZlRxYgEXtgZOzFZfVAuLAqiXyBfsTAJZVnYNeFueuoFRngGNBrxyExEyNKzMkzNrWr" ascii wide 
       condition: 
              3 of them 
}
