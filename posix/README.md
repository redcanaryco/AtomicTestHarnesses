# Install instructions
To install the Posix Atomic Test Harness simply run
```python
pipenv install posixath
```

or 

```python
pip install posixath
```
then follow the instructions below for how to run the tests

# Running the tests (simple)
The `posixath` package contains all the code necessary to run myriad attack techniques for both Linux and macOS. Below are a few examples of how to run the various tests. For more information run. If you want more examples of how to run very specific tests please refer to the documentation for that specific technique.
```python
python -m posixath --help
```

## Viewing available tests
To view the available tests run 
```python
python -m posixath [linux|macos] --list
```

## Running a specific attack technique
To run a specific attack technique you need to specify the platform and the technique as follows
```python
python -m posixath linux -t T1018
```
or for macOS
```python
python -m posixath macos -t T1059
```

# Documentation
We use a variation on `mkdocs` for our documentation. All of the documentation is housed in the docs folder of the repo. They are markdown files and so can be easily viewed in github or in any standard markdown viewer. You can also use the python library `mkdocs-material` to generate a more friendly local web view of the documentation. To do so make sure you have the dev dependencies listed in the Pipfile installed. Then run `mkdocs serve` from the root directly. This will create a web server that listens on localhost and provides a nice web UI for viewing the documenation.

# Dependencies
## Linux
Some test require that the user be `root` in order to run. 

Below is a list of packages required for being able to run the posix tests
### Ubuntu
```bash
$ sudo apt-get install libcap-dev
```

### Fedora
```bash
$ sudo dnf install libcap-devel
```

# Advanced Usage
You can use the Posix Atomic Test Harnesses directly from the code base as well. The following instructions will walk you through
how to setup your environment so that you can run the tests directly from the source. Running tests this way allows you to use any
tools that operate with `pytest` itself.

## pytest runner
Pytest is used as our test runner to execute various Atomic Test Harness tests. In order to prepare your environment please run:

```python
pipenv install
pipenv shell
pytest -k [linux|macos] -v
```
> NOTE: If you don't have `pipenv` installed please see the guide [here](https://pipenv.pypa.io/en/latest/install/)

### Running the tests
The tests can be run two different ways. The first is by cloning the repo and calling directly into pytest. The second is by installing the code base from PyPi.

### Enumerate the different types of tests that can be run
`pytest --co`

### Enumerate the various command line parameters
`pytest --help` and look for the custom options section

or

`pytest --fixtures`

### Enumerate the different types of linux tests
`pytest -v -m linux --co`

### Enumerate the different types of macOS tests
`pytest -v -m macos --co`

### Enumerate attack variations for a given technique
`pytest -v -m linux -k T1548_001 --co`

### Run all linux tests
`pytest -v tests/linux`

or

`pytest -v -m linux`

### Run all macOS tests
`pytest -v tests/macos`

or

`pytest -v -m macos`

### Run a specific attack type for linux
`pytest -v -m linux -k T1548_001`

### Run a specific attack type variation for linux
`pytest -v -m linux -k T1548_001 -k chmod`

### Run a specific attack type for macOS
`pytest -v -m macos -k T1018`
