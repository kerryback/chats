# chats

Password-protected reader, published at https://chats.kerryback.com.

The repo holds only encrypted data. `docs/data/` is AES-256-GCM ciphertext, with the key derived from the password by PBKDF2-SHA256 at 600,000 iterations. The browser decrypts it after the password is entered. The source files stay local and are excluded by `.gitignore`.

## Publish new conversations

1. Add the Markdown files to `conversations/`. Name each file `NNN YYYY-MM-DD Title.md`.
2. Run `node build.mjs`.
3. Commit and push `docs/`.

The build skips files from 2025, from January through March 2026, and from April 2, 2026, except the dates in `KEEP_DATES` and the conversation numbers in `KEEP_CHATS` in `build.mjs`.

## Change the password

1. Set `CHAT_PASSWORD` in `.env`.
2. Run `node build.mjs`. This re-encrypts every file with a new salt.
3. Commit and push `docs/`.

The old ciphertext stays in git history and still opens with the old password.
