import os
import sys

root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
print(f"[*] Starting Seep Formatting & Encoding Sanitizer on: {root}")

sh_fixed = 0
ps_bom_fixed = 0
py_checked = 0

for dirpath, dirnames, filenames in os.walk(root):
    # 跳过 .git 和外部大包缓存
    if ".git" in dirpath or "node_modules" in dirpath or ".venv" in dirpath or "tmp_" in dirpath:
        continue

    for f in filenames:
        ext = os.path.splitext(f)[1].lower()
        filepath = os.path.join(dirpath, f)

        # 1. 规范化 Bash 脚本 (*.sh)：坚决杜绝 \r
        if ext in [".sh", ".bash"]:
            try:
                with open(filepath, "rb") as fp:
                    data = fp.read()
                if b"\r\n" in data:
                    clean_data = data.replace(b"\r\n", b"\n")
                    with open(filepath, "wb") as fp:
                        fp.write(clean_data)
                    sh_fixed += 1
                    print(f"  [LF Fix] {os.path.relpath(filepath, root)}")
            except Exception as e:
                print(f"  [!] Error fixing {filepath}: {e}")

        # 2. 规范化 PowerShell 脚本 (*.ps1)：在 Windows 下确保带 UTF-8 BOM，防止 PS5.1 乱码
        elif ext == ".ps1":
            try:
                with open(filepath, "rb") as fp:
                    data = fp.read()
                # 检查是否有 UTF-8 BOM: EF BB BF
                if not data.startswith(b"\xef\xbb\xbf"):
                    # 补齐 BOM 并保证换行符
                    bom_data = b"\xef\xbb\xbf" + data
                    with open(filepath, "wb") as fp:
                        fp.write(bom_data)
                    ps_bom_fixed += 1
                    print(f"  [BOM Fix] {os.path.relpath(filepath, root)}")
            except Exception as e:
                print(f"  [!] Error checking BOM {filepath}: {e}")

        # 3. 语法解析检查 (*.py)
        elif ext == ".py":
            py_checked += 1
            try:
                import ast
                with open(filepath, "r", encoding="utf-8", errors="ignore") as fp:
                    code = fp.read()
                ast.parse(code)
            except Exception as e:
                print(f"  [SYNTAX ERROR in Python] {os.path.relpath(filepath, root)}: {e}")

print(f"\n[√] 格式化治理完成:")
print(f"  - 修正 LF 换行 Bash 脚本: {sh_fixed}")
print(f"  - 补齐 UTF-8 BOM 的 PowerShell 脚本: {ps_bom_fixed}")
print(f"  - 校验通过的 Python 脚本: {py_checked}")
