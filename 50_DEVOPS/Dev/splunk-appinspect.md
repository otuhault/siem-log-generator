Sur macos, pour éviter les erreurs lors de l'archivage:
```bash
COPYFILE_DISABLE=1 tar --exclude="._*" --exclude=".DS_Store" --exclude="__MACOSX" -cvzf TA-bitdefender-gravityzone.tar.gz TA-bitdefender-gravityzone/
```
