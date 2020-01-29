# Cripta
> Cripta is a simple python program that allows to encrypt files from the command line to password protect them.


The program allows to encrypt the contents of files with a passord and to decrypt them given their path.
The usage from the terminal is the following:

```
Usage:
  cripta.py encrypt <files> ... [--copy]
  cripta.py decrypt <files> ... [--copy]
  cripta.py (-h | --help)
  cripta.py --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  -c --copy     Preserves the original encrypted or unencrypted files.
```


## Installation

It requires a python 3 interpreter and the following pip-installable packages:
* [docopt](https://github.com/docopt/docopt)
* [cryptography](https://cryptography.io/en/latest/)

## Usage example

```
$ ls
plaintext.txt
$ python cripta.py encrypt ./plaintext.txt
$ ls 
plaintext.txt.cri
$ python cripta.py decrypt ./plaintext.txt.cri
$ ls
plaintext.txt
```


## Release History

* 0.1
    * First simple working version.

## Others

Contact: jacobo.baldonedo@gmail.com

Distributed under the MIT License. See ``LICENSE.txt`` for more information.

[https://github.com/jacoboglez](https://github.com/jacoboglez)
