# Any Other Language (Rust, Swift, Kotlin-native, Dart/Flutter, Elixir, Erlang, Perl, Lua, R, Haskell, Clojure, Solidity, shell, etc.)

When a language has no dedicated reference, **derive the source/sink/sanitizer model yourself**. The method is the same everywhere:

1. **Identify the I/O boundary.** Find the web framework or entry mechanism (routes, handlers, CLI parsing, message consumers, RPC). Everything those receive is a **source**.
2. **Enumerate the dangerous capability classes** and find this language's API for each:

| Capability | Look for the language's... | Typical names |
|---|---|---|
| Database query | raw SQL execution APIs | `query`, `execute`, `exec`, `raw`, `sql`, `prepare` |
| Process execution | shell / process spawn | `system`, `exec`, `spawn`, `Command`, `os.cmd`, `Process`, `` ` `` |
| Dynamic code | evaluators, dynamic require/import | `eval`, `load`, `compile`, `Code.eval_string`, `loadstring`, `parse+eval` |
| Filesystem | open/read/write/delete by path | `open`, `File.*`, `readFile`, `Path` |
| Network fetch | HTTP clients, sockets | `get`, `request`, `fetch`, `HTTPoison`, `URLSession`, `http.get` |
| HTML output | template raw-output escapes | `raw`, `safe`, `unescaped`, `html_safe`, `{{{`, `Phoenix.HTML.raw` |
| Deserialization | native object formats | `binary_to_term` (Erlang/Elixir; use `[:safe]`), `Storable::thaw` (Perl), `NSKeyedUnarchiver` (Swift: use `requiresSecureCoding`), `readRDS` |
| Redirect | HTTP redirect helpers | `redirect`, `Location` header |
| Crypto/randomness | hash, cipher, RNG APIs | `md5`, `sha1`, `ECB`, non-CSPRNG `rand` |

3. **Find the sanitizers**: parameter binding, escaping helpers, typed parsing, allow-lists, framework auto-escaping. Confirm from the framework's docs knowledge that they apply to that sink.
4. **Trace** exactly as in `taint-methodology.md`.

## Language-specific quick notes
- **Elixir/Phoenix**: `Ecto.Adapters.SQL.query(Repo, "..." <> x)` / `fragment("... #{x}")` is not allowed at compile time, but `Ecto.Query.API.fragment` with string interpolation in a macro is; `String.to_atom(user)` (atom table exhaustion DoS); `:erlang.binary_to_term(user)` without `[:safe]`; `raw/1` in HEEx; `System.cmd` is arg-array safe but `:os.cmd(user)` is a shell.
- **Perl**: 2-arg `open(FH, $user)` (command execution with `|`), backticks, `system($str)`, `eval $str`, DBI `do("...$x")` (use placeholders), `-T` taint mode absent.
- **Lua/OpenResty**: `loadstring`, `os.execute`, `io.popen`, `ngx.var.*` sources, `ngx.redirect(user)`.
- **Swift/iOS**: `WKWebView.evaluateJavaScript(user)`, `loadHTMLString(user)`, `NSPredicate(format: user)`, `NSKeyedUnarchiver.unarchiveObject`, Keychain vs `UserDefaults` for secrets, `NSAllowsArbitraryLoads` in Info.plist, URL scheme handlers as sources.
- **Dart/Flutter**: `Process.run('sh', ['-c', x])`, `rawQuery('...$x')` (sqflite: use `?` args), WebView `runJavascript(x)`, secrets in `lib/` (shipped in the app), `badCertificateCallback = (..) => true`.
- **Solidity**: reentrancy (external call before state update), `tx.origin` auth, unchecked `call` return, `delegatecall` to user address, integer overflow (< 0.8), missing access modifiers (`onlyOwner`), `block.timestamp` randomness, unprotected `selfdestruct`/initializers.
- **Shell scripts**: unquoted `$var` (word splitting, glob), `eval "$x"`, `curl | sh`, `rm -rf "$DIR/"` with empty var, secrets echoed, `set -x` leaking secrets, temp files in `/tmp` with predictable names.
- **R**: `eval(parse(text = user))`, `system(paste(...))`, `dbGetQuery(con, paste0(...))`, Shiny `renderUI(HTML(user))`.
- **Haskell**: `unsafePerformIO`, `rawSystem` is safe but `system`/`callCommand` take a shell string, raw SQL `query_` with `fromString`.

If you cannot tell whether an API is dangerous in a less-common language, report the finding with `confidence: Low` and explain the doubt. Do not drop it silently or overstate it.
