# ZorgDocZoek
 encrypted document database with password, categories, drag &amp; drop and document viewer

 What is ZorgDocZoek?
ZorgDocZoek is a secure, local knowledge base for healthcare documents. All documents and the category structure are stored encrypted (AES via Fernet) in a single SQLite database file (knowledgebase_secure.db). No readable content is ever written to disk.

Password
On first run you choose a database password. On every following start you enter this password to unlock the database (up to 5 attempts).

Note: the password cannot be recovered. If you lose it, the contents of the database are permanently unreadable. Keep it somewhere safe, for example in a password manager.

Adding documents
• 📄 Upload to category: first select a category in the left tree, then add documents straight into it.
• ⬆ Upload loose: add documents without a category; they appear in the 'Uncategorized' list.
Supported file types: PDF (.pdf), Word (.docx) and text (.txt). The text of each document is read automatically so you can search it. If you upload the same file again, the existing version in the database is updated.

Categories
• 📁 New category: creates a category under the selected category (or in the root).
• ✏️ Rename and 🗑️ Delete act on the selected category.
• Drag and drop: drag documents or whole categories onto another category to move them. You can also drag documents out of 'Uncategorized' onto the tree to file them.

Searching
Type one or more search terms in the search field and press Enter or click 'Search'. A document is a match when all terms appear in it. Searching works by decrypting documents in memory; no unencrypted search index is kept on disk (privacy-first). An empty search field shows the full list again.

Viewing and summarizing
• Click a document once (in the tree, the search results or 'Uncategorized') for a preview and an automatic summary in the right-hand panel.
• Double-click a document to open the original. The file is then temporarily decrypted to a temporary file and opened in the default program (e.g. Word or your PDF reader).

Backup
Everything lives in a single file: knowledgebase_secure.db. Copy this file regularly to a safe backup location. Together with your password, that is all you need to restore your knowledge base.



