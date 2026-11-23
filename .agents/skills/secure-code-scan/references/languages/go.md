# Go (net/http, Gin, Echo, Fiber, chi, gorilla/mux, GORM, sqlx)

## Sources
- net/http: `r.URL.Query().Get`, `r.URL.Path`, `r.URL.RawQuery`, `r.FormValue`, `r.PostFormValue`, `r.Form`, `r.PostForm`, `r.MultipartForm`, `r.FormFile` (header `.Filename`), `r.Body` (via `json.NewDecoder(r.Body).Decode`), `r.Header.Get`, `r.Cookie`, `r.Host`
- Gin: `c.Query/DefaultQuery/Param/PostForm/GetHeader/Cookie/FormFile`, `c.Bind*/ShouldBind*` structs
- Echo: `c.QueryParam/Param/FormValue/Bind`; Fiber: `c.Query/Params/FormValue/BodyParser/Get`
- chi: `chi.URLParam`; gorilla: `mux.Vars(r)`; gRPC request messages; `os.Args`, `flag.*`

## Sinks
| Class | Sinks |
|---|---|
| SQL | `db.Query/QueryRow/Exec(+Context)` with `fmt.Sprintf` or `+`; sqlx `Select/Get/NamedExec` with concatenated SQL; GORM `Raw/Exec(fmt.Sprintf)`, `Where(fmt.Sprintf(...))`, `Where(userString)` (string condition), `Order(user)`, `Select(user)`, `Group/Having/Joins(user)`; squirrel `Expr(user)` |
| Command | `exec.Command("sh", "-c", user)`, `exec.Command(user, ...)`, args starting with `-` (argument injection), `syscall.Exec` |
| Path | `os.Open/OpenFile/ReadFile/WriteFile/Create/Remove(All)`, `ioutil.*`, `http.ServeFile(w, r, user)`, `filepath.Join(base, user)` (Join cleans but does **not** prevent `../` escaping base), zip/tar extraction using `f.Name` (zip slip); `http.Dir` + `http.FileServer` is safe |
| SSRF | `http.Get/Post/Head(user)`, `http.NewRequest(method, user, ...)`, `net.Dial(user)`, resty `R().Get(user)` |
| XSS | `text/template` used for HTML (no escaping), `template.HTML(user)`, `template.JS/URL/HTMLAttr(user)`, `w.Write([]byte(user))`/`fmt.Fprintf(w, user)` with HTML content type; Gin `c.Data(200, "text/html", user)` |
| Redirect | `http.Redirect(w, r, user, ...)`, `c.Redirect(code, user)` |
| Format | `fmt.Sprintf(user)` (no RCE, but info leak), `log.Printf(user)` |
| Unsafe | `unsafe.Pointer`, cgo boundaries, `reflect` with user names |
| Deserialization | `encoding/gob` from untrusted sources (DoS), YAML into `interface{}` (resource exhaustion), `xml.Unmarshal` (no XXE, but billion-laughs-style DoS in older Go) |
| Concurrency | data races on shared maps or counters in handlers (no mutex), `time-of-check` on balances |

## Sanitizers / safe APIs
- SQL: placeholders (`?` MySQL/SQLite, `$1` Postgres) with args: `db.Query("... WHERE id = $1", id)`; GORM `Where("name = ?", v)`, struct/map conditions; identifier allow-list for `Order`.
- Command: `exec.Command(fixedBinary, args...)` with an allow-list and a `--` separator; never `sh -c` with input.
- Path: `filepath.Clean` + `filepath.Rel(base, p)` and reject results starting with `..`; Go 1.24 `os.Root` / `os.OpenInRoot`; `filepath.IsLocal` (Go 1.20+).
- HTML: `html/template` (contextual auto-escaping); `bluemonday` for rich text.
- Types: `strconv.Atoi` / `uuid.Parse` conversions constrain input.

## Notes
- `"math/rand"` for tokens/IDs → `"crypto/rand"`. `crypto/md5`/`sha1` for passwords → `golang.org/x/crypto/bcrypt` or `argon2`.
- `tls.Config{InsecureSkipVerify: true}`, `MinVersion` below TLS 1.2.
- `http.ListenAndServe` without timeouts (`ReadHeaderTimeout`): Slowloris DoS, Low (gosec G112).
- CORS: `rs/cors` `AllowedOrigins: []string{"*"}` with `AllowCredentials: true`, or `AllowOriginFunc` returning `true`.
- Error handling: ignored `err` on security-relevant calls (`_ = bcrypt.CompareHashAndPassword`), defer-close ignored. Fail-open pattern: `if err != nil { log; }` followed by continuing as authorized.
- JWT (`golang-jwt`): missing `jwt.WithValidMethods`, keyfunc not checking `token.Method`.
