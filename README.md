## Building & Running

Build and run the application:
```bash
cmake -S . -B build
cmake --build build
./build/password_manager
```

Run tests:
```bash
ctest --test-dir build --output-on-failure
```

Clean the build outputs:
```bash
cmake --build build --target clean
```

## Commands
- `l` — List all stored accounts with numerical IDs
- `s <nr>` — Show full decrypted details (username, password, email, URL, comment)
- `a` — Add new entry (with duplicate name protection and optional password generator)
- `d <nr>` — Delete entry and re-save
- `p` — Change master password and re-encrypt entire database
- `q` — Quit and cleanly release all allocated heap memory

