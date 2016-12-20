# tajna

## Setup

*Step 1*: You'll need `gpg2` installed to use `tajna`.
- Ubuntu: `apt-get install gnupg2`
- Macos: https://gpgtools.org/

You'll need to generate a key.

*Step 2*: enter your identity into `~/.tajna/identity

```
mkdir -p ~/.tajna/
echo "Your Name" > ~/.tajna/identity
```

*Step 3*: Run `tajna init` to initialise secrets file.

It will ask for the passphrase of the key found using the identity.

*Step 4*: Done. See `tajna --help` for the list of commands and options.
