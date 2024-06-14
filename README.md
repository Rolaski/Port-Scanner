# Port-Scanner

An application that works to scan a range of TCP and UDP ports for an IP address.
This is a final project for the subject - Computer Networks
<br> 
<hr>

## Preparing the input file
The input project is protected by validation in the code but it still needs the following data
 - IP address
 - TCP port range
 - UDP port range
 
An example input.txt file should look like this:<br>
127.0.0.1,1-300,1-800<br>
192.168.1.1,1-100,1-300

<hr>

## How to run?
 - Install python version 3.12 or higher on your computer
 - Add it to your environment variables (PATH)
 - Instal [Nmap](https://nmap.org/download.html)
 - Add it to your environment variables (PATH)
 - Go to the Port-Scanner -> dist folder
 - Run scanner.exe
 - Provide the input file path
 - Provide the output file path, if you entered a non-existent .txt file it will be created
 - Wait until port scanning is performed
 - Ready! The information is in the output file

<hr>

## Important
The application was created mainly to pass a course at university, so the code and comments were written in Polish, actually it's a bit stupid on my part, but that's how it goes. 
If you need translation or have questions about the operation of the program, please write to me
