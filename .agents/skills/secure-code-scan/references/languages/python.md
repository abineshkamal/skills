# Python (Django, Flask, FastAPI, DRF, SQLAlchemy, Celery, scripts)

## Sources
- Flask: `request.args/form/values/json/get_json()/data/files/cookies/headers/view_args`, route params `<id>`
- Django: `request.GET/POST/body/FILES/COOKIES/META` (incl. `HTTP_*` headers), URL kwargs, DRF `request.data/query_params`, serializer `validated_data` (still tainted unless the field type constrains it)
- FastAPI/Starlette: path/query/body params in endpoint signatures, Pydantic models (a typed `int`/`EmailStr`/`Literal` field constrains; a plain `str` does not), `Request.query_params/json()/form()`, `UploadFile.filename`
- `input()`, `sys.argv`, `argparse` args (CLI tools), `os.environ` (only if attacker-influenced), Celery task args from untrusted producers, file contents, `email`/`csv` parsing of user files, LLM output

## Sinks
| Class | Sinks |
|---|---|
| SQL | `cursor.execute(f"...{x}")` / `"..." % x` / `.format()` / `+`; `executescript`; Django `raw()`, `extra()`, `RawSQL()`, `cursor.execute` with formatting, `.annotate(RawSQL)`; SQLAlchemy `text(f"...")`, `engine.execute(str)`, `session.execute(f"...")`, `literal_column(user)`, `order_by(text(user))`; pandas `read_sql(f"...")` |
| Command | `os.system`, `os.popen`, `subprocess.*(..., shell=True)`, `subprocess.run(f"cmd {x}", shell=True)`, `commands`, `pty.spawn`, `asyncio.create_subprocess_shell`; argument injection with `shell=False` lists when a user value can start with `-` |
| Code | `eval`, `exec`, `compile`, `__import__(user)`, `importlib.import_module(user)`, `getattr(module, user)()`, `pickle` (see deserialization), Jinja `Template(user).render()` |
| Deserialization | `pickle/cPickle/dill/joblib/shelve.load(s)`, `yaml.load` without `SafeLoader` / `yaml.unsafe_load` / `yaml.full_load` (pre-5.4), `jsonpickle.decode`, `marshal.loads`, `torch.load` without `weights_only=True`, `numpy.load(allow_pickle=True)` |
| SSTI | `render_template_string(user)`, `jinja2.Template(user)`, `Environment().from_string(user)`, Django `Template(user).render`, Mako `Template(user)` |
| XSS | `Markup(user)`, `mark_safe(user)`, `format_html` misuse, `|safe`, `{% autoescape off %}`, `Environment(autoescape=False)` (Jinja2's default when created manually), `HttpResponse(f"<html>{x}")`, `make_response(f"...")` with HTML content type |
| Path | `open(user)`, `send_file(user)`, `send_from_directory` (safe for filename, unsafe for directory), `FileResponse(open(...))`, `os.path.join(base, user)` (absolute user path discards base!), `pathlib.Path(base) / user`, `shutil.*`, `tarfile.extractall()` without `filter='data'` (Python ≥3.12) / `zipfile.extractall()` (zip slip) |
| SSRF | `requests.*`, `httpx.*`, `urllib.request.urlopen`, `aiohttp`, `urllib3`, `pycurl`, `PIL.Image.open(urlopen(user))`, `pdfkit/weasyprint` with user URLs or HTML |
| Redirect | `redirect(request.args['next'])`, `HttpResponseRedirect(user)`, `RedirectResponse(user)` |
| XXE | `lxml.etree.parse/fromstring` with `XMLParser(resolve_entities=True)` (pre-5.x default), `xml.dom.minidom`, `xml.sax` with feature_external_ges. Recommend `defusedxml` |
| LDAP | `ldap.search_s(base, scope, f"(uid={u})")` |
| Logic | `assert` used for security checks (stripped with `-O`) |

## Sanitizers / safe APIs
- SQL: DB-API placeholders `cursor.execute("... WHERE id = %s", (id,))` (`?` for sqlite3); Django ORM filters; SQLAlchemy bound params `text("... :id").bindparams(id=x)`; `sql.Identifier` (psycopg) for identifiers.
- Command: `subprocess.run([...], shell=False)` + allow-list; `shlex.quote` when a shell is unavoidable.
- HTML: Jinja2/Django autoescape (Flask enables it for `.html` templates), `markupsafe.escape`, `bleach.clean`/`nh3.clean` for rich text.
- Path: `werkzeug.utils.secure_filename`, `os.path.realpath` + `os.path.commonpath([base, p]) == base`, `Path.resolve().is_relative_to(base)`.
- Deserialization: `yaml.safe_load`, `json.loads`, `torch.load(..., weights_only=True)`.
- Validation: Pydantic/DRF field types that constrain (int, UUID, Enum, `constr(pattern=...)`).

## Framework notes
- Django: `DEBUG=True`, `ALLOWED_HOSTS=['*']`, hard-coded `SECRET_KEY`, `@csrf_exempt`, `SESSION_COOKIE_SECURE=False`, `SECURE_SSL_REDIRECT` absent, `X_FRAME_OPTIONS`; DRF `permission_classes = [AllowAny]` on sensitive views; `DEFAULT_PERMISSION_CLASSES` missing (DRF default is AllowAny!); `ModelSerializer` with `fields='__all__'` (mass assignment and over-exposure).
- Flask: `app.run(debug=True)` (Werkzeug debugger = RCE), `app.secret_key` hard-coded, no CSRF (Flask-WTF absent) on cookie sessions; `session` is client-side signed, not encrypted.
- FastAPI: endpoints without `Depends(get_current_user)`; `CORSMiddleware(allow_origins=["*"], allow_credentials=True)`.
- `hashlib.md5/sha1` for passwords; use `argon2-cffi`/`bcrypt`/`passlib`/Django hashers. `random` for tokens → use `secrets`.
- `requests(..., verify=False)`; also missing `timeout=` (resource exhaustion, Low).
- `tempfile.mktemp` (race) → `NamedTemporaryFile`/`mkstemp`.
