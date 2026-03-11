# charsec

This is a library that allows you to encode arbitrary data in text, ranging from code that executes hidden code in itself to jpegs in text files.

There could be security vulnerabilities associated with this, so the CLI also includes `scan` and `remove` commands to automatically scan a directory or file for hidden data, and/or remove it.

You can install it like so:

```sh
# basic pip install
pip install charsec
# recommended
uv add charsec
# if you only want to use the CLI
pipx install charsec
```

Once installed run:

```sh
charsec --help
```

To confirm installation and see available commands.