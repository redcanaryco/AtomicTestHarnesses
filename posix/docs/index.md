# Home

## Posix Atomic Test Harness
This project is a suite of tests for generating high fidelity telemetry mapped to MITRE ATT&CK techniques. The project is divided in two main components i.e. the macOS tests and the Linux tests. For each attack technique, there is an associated documentation page that will go into more detail about the tests that are being run, how to run them, the expected output, and any important things to be aware of.

## Commands
Under the hood the poisx atomic test harnesses use pytest. Because of this some of the syntax you will see will be very similar to Pytest since we are passing some of the arguments through. Lets walk through how different levels of tests can be specified

To run all the platform specific tests i.e. Linux or macOS you can use the following command
```python
python -m posixath [macos|linux]
```

To run a specific attach technique for a given platform you can run the following command
```python
python -m posixath [macos|linux] -t <attack_id>
```

You can get even more specific with which tests you want to run. The first thing to know is how to view what tests are available. There is a hierarchical structure to the tests that are as follows:
- Platform i.e. linux or macOS
  - Technique
    - Group
      - Test
        - Test Variation

In order to view the various tests you can use the `--list` option at either the platform level or the technique id level
```python
python -m posixath [macos|linux] --list
```
```python
python -m posixath [macos|linux] -t <technique_id> --list
```

Below is the output of the `--list` option for a specific attack technique
```
Attack id: T1548_001
  Group: TestSetUid
    chmod[4755]
    chmod[u+s]
    chmod[--reference=myfile.txt]
    install[--mode 4755]
    install[--owner=root --mode=4755]
    rsync[--chmod=4755 --perms]
    syscall
  Group: TestSetGid
    chmod[2755]
    chmod[g+s]
    chmod[--reference=myfile.txt]
    install[--mode 2755]
    install[--owner=root --mode=2755]
    rsync[--chmod=2755 --perms]
    syscall
```

The output shows the attack technique ids, the Group, the individual tests, and variations on some individual tests. In oder to specify a specific test you can use Pytest's keyword matching system. To do this specify the `-k` option with a string that matches keywords at the group, test, or test variation level. Below are a few examples. More examples will be given in the documetation for each technique

This will run the `syscall` test that is part of the `TestSetGid` group
```python
python -m posixath linux -t T1548_001 -k "TestSetGid and syscall"
```

This command will run only the `2755` variation of the `chmod` test in the `TestSetGid` class
```python
python -m posixath linux -t T1548_001 -k "TestSetGid and chmod and 2755 and not rsync"
```

This will run just the `osascript` variation of the `T1059_002` technique
```python
python -m posixath macos -t T1059_002 -k "osascript"
```

