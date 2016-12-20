This is a description about my attempt to solve the memory analysis challenge in SECCON 2016 qualifier held on December 10 and 11. Although I could not solve the challenge, I realized that I was really close after I read a writeup. I decided to write a post about my approach and the mistake I made. 


The filename was 'forensics_100.raw' and a short version of the challenge description is as follows :

***

Memory Analysis


Find the website that the fake svchost is accessing.

You can get the flag if you access the website

Hint1: http://www.volatilityfoundation.org/

Hint2: Check the hosts file

***

I had done one small assignment in my forensics class using volatility and hence I was a bit familiar with the tool. The first thing to do was to determine the type of the operating system. Identifying the profile can help later during investigation. 


`volatility -f forensic_100.raw imageinfo`

As the hint stated that we should look at the host file, I googled a few terms related to DNS and volatility. I found some tips in the Google books version of "The Art of Memory Forensics: Detecting Malware and Threats in Windows, Linux, and Mac Memory". A link to the section is given at the end of this post. 


`1. volatility -f forensic_100.raw --profile WinXPSP2x86 filescan | grep -i hosts`

`2. volatility -f forensic_100.raw --profile WinXPSP2x86 dumpfiles -Q 0x217b748 -D OUTDIR --name`


These two commands give us the host file contents. Please note that the address '0x217b748' is obtained in the output of the filescan command. 
Running strings command on the output file created by the dumpfiles plugin gives you this: 


```
\#Copyright (c) 1993-1999 Microsoft Corp.

\#This is a sample HOSTS file used by Microsoft TCP/IP for Windows.

\#This file contains the mappings of IP addresses to host names. Each

\#entry should be kept on an individual line. The IP address should

\#be placed in the first column followed by the corresponding host name.

\#The IP address and the host name should be separated by at least one

\#space.

\#Additionally, comments (such as these) may be inserted on individual

\#lines or following the machine name denoted by a '\#' symbol.

\#For example:

\#      102.54.94.97     rhino.acme.com          \# source server

\#       38.25.63.10     x.acme.com              \# x client host

127.0.0.1       localhost

153.127.200.178    crattack.tistory.com
```


Now I was sure that the flag is on this website. The website was quite big and I could not find anything interesting just by browsing. After this, the logical approach would have been to detect the fake svchost process and try to find the URLs of the domain "crattack.tistory.com" it had accessed. I did play around with the dumps of all processes named svchost but my approach to find the fake process was flawed.

The next step I did was to run strings on the whole dump and grep for "crattack.tistory.com". There were only two unique URLs in output and I tried accessing both. 

http://crattack.tistory.com/entry/Data-Science-import-pandas-as-pd

http://crattack.tistory.com/favicon.ico

still nothing ....

The important point I missed here was that the IP of crattack.tistory.com was 153.127.200.178 at the time of capturing image of the memory. It was changed at some point after the imaging was done. After the competition ended, I read a write-up and realized that the web server on 153.127.200.178 was still accessbile and simply entering the IP address instead of the domain name would have given me the flag. 

I want to point out that there was actually no need to look for a fake svchost process to solve the challenge. 


Flag URL: http://153.127.200.178/entry/Data-Science-import-pandas-as-pd


Flag: SECCON{_h3110_w3_h4ve_fun_w4rg4m3_} 

References : 
[Google books link to a section of "The art of memory forensics" ](https://books.google.com/books?id=U1jOAwAAQBAJ&pg=PA339&lpg=PA339&dq=dnscache+plugin+volatility&source=bl&ots=yhwCWBV0-m&sig=4yrdcupNoRUBbBKopq3IIWZvWrk&hl=en&sa=X&ved=0ahUKEwiCnJ6y3_TQAhWHj1QKHSCrCR4Q6AEIOjAF#v=onepage&q=dnscache%20plugin%20volatility&f=false)

https://ctftime.org/task/3173

