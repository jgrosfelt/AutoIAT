README

Automatically analyze the Import Address Table (IAT)

Depends on PEFile module

Usage: autoiat.py -i <WindowsApplication>


This is a python tool that will extract the Import Address Table (IAT) table 
from a PE file and then automatically provide a description of what the 
imported function do as well as provide details of how they can be 
used maliciously (if applicable).

Copyright (c) 2013 Justin Grosfelt jgrosfelt@gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Also, thanks to Michael Sikorski and Andrew Honig for allowing me to use their 
Windows functions descriptions in Section "A. Important Windows Functions" of 
their book Practical Malware Analysis.

Michael Sikorski, Andrew Honig. Practical Malware Analysis.  
No Starch Pres. 1 edition. February 29, 2012.
http://practicalmalwareanalysis.com/
http://www.amazon.com/Practical-Malware-Analysis-Hands-Dissecting/dp/1593272901