#!/usr/bin/env python3
"""Guard strstr() in gum_quick_exception_is_interrupt against a NULL message.

JS_ToCString() returns NULL when it cannot convert the exception to a string
(which happens in the barebone kernel agent), and the code passes it straight
to strstr(), dereferencing NULL.  Add the missing NULL check.
"""

import sys

OLD = """  message = JS_ToCString (ctx, exception);
  is_interrupt = strstr (message, "InternalError: interrupted") != NULL;
  JS_FreeCString (ctx, message);"""

NEW = """  message = JS_ToCString (ctx, exception);
  is_interrupt = message != NULL &&
      strstr (message, "InternalError: interrupted") != NULL;
  JS_FreeCString (ctx, message);"""


def patch(path):
    with open(path, encoding="utf-8", newline="") as f:
        text = f.read()

    text = text.replace("\r\n", "\n")
    old = OLD.replace("\r\n", "\n")
    new = NEW.replace("\r\n", "\n")

    if old not in text:
        print(f"ERROR: anchor not found in {path}", file=sys.stderr)
        return False

    text = text.replace(old, new, 1)

    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    print(f"patched {path}: NULL-guard strstr in gum_quick_exception_is_interrupt")
    return True


def main():
    if len(sys.argv) < 2:
        print("usage: patch-gum-exception-null.py <gumquickcore.c>",
              file=sys.stderr)
        return 1
    ok = True
    for path in sys.argv[1:]:
        ok = patch(path) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
