# Kerberos
Computer-network authentication protocol

Kerberos is a computer-network authentication protocol that works on the basis of tickets to allow end systems to communicate over an unsecured channel using symmertric key encryption where each end system has a single shared key with authentication server, which authenticates user and provides further communication with ticket granting server, which grants a common ticket for two end systems to communicate with symmetric key encryption.

The above code is an implementation of Kerberos protocol in Pure Python. I skipped timestamp verification, although I added timestamp. The cipher used in this code is basic stream cipher which is fast and easy to understand. I used really long variable names in this code with which it orients towards more readability.
