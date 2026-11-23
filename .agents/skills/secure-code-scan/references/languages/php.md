# PHP (Laravel, Symfony, CodeIgniter, WordPress, plain PHP)

## Sources
- `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES` (`name`, `type` attacker-controlled), `$_SERVER['HTTP_*' | 'REQUEST_URI' | 'QUERY_STRING' | 'PHP_SELF' | 'PATH_INFO']`, `php://input`, `getallheaders()`
- Laravel: `$request->input/get/query/post/all/only/except/json/route/header/cookie/file`, `request('x')`, `Request::input`, route parameters, `$request->validated()` (only constrained if the rules constrain format), Livewire public properties (client-controllable!)
- Symfony: `$request->query/request/attributes/cookies/headers/files->get()`, `getContent()`, `#[MapRequestPayload]`
- CodeIgniter: `$this->input->get/post`, `$this->request->getVar/getGet/getPost/getJSON`
- WordPress: `$_GET/$_POST` in hooks, `get_query_var`, REST `$request['x']`, AJAX handlers `wp_ajax_nopriv_*` (**unauthenticated**)

## Sinks
| Class | Sinks |
|---|---|
| SQL | `mysqli_query`, `mysql_query`, `$pdo->query/exec`, `$pdo->prepare("... $x")` (prepared but interpolated), `pg_query`; Laravel `DB::raw`, `DB::select/statement/unprepared("... $x")`, `whereRaw/selectRaw/orderByRaw/havingRaw/groupByRaw`, `orderBy($request->col)` (column injection), `->where($request->col, ...)` key from input; Doctrine `createQuery("... $x")`, DBAL `executeQuery` concat; WordPress `$wpdb->query/get_results("... $x")` without `$wpdb->prepare` |
| Command | `exec`, `shell_exec`, `system`, `passthru`, `popen`, `proc_open`, `pcntl_exec`, backticks, `mail()` 5th parameter, Symfony `Process::fromShellCommandline` |
| Code | `eval`, `assert($str)` (PHP < 8), `create_function`, `preg_replace` with `/e` (PHP < 7), `call_user_func($user)`, `$func()` variable functions, `$$var`, `extract($_REQUEST)`, `parse_str($str)` without a 2nd arg (PHP < 8), `unserialize` |
| Inclusion | `include/require(_once)` with input (LFI/RFI, `php://filter`, log poisoning) |
| XSS | `echo/print $x`, `<?= $x ?>`, `printf`; Blade `{!! $x !!}`; Twig `|raw`, `{% autoescape false %}`; WordPress output without `esc_html/esc_attr/esc_url/wp_kses` |
| Path | `file_get_contents`, `fopen`, `readfile`, `file`, `unlink`, `copy`, `rename`, `file_put_contents`, `move_uploaded_file` dest, `scandir`, `Storage::get/download($user)`, `response()->download($user)`, `ZipArchive::extractTo` |
| SSRF | `curl_setopt(CURLOPT_URL, $user)`, `file_get_contents($url)`, `fopen($url)`, `Http::get($user)`, Guzzle `->get($user)`, `get_headers`, `SoapClient($wsdl)`, `getimagesize($url)` |
| Deserialization | `unserialize($user)` (POP chains via Laravel/Monolog/Guzzle gadgets), `phar://` wrapper on any file function with user path, `yaml_parse` with callbacks |
| XXE | `simplexml_load_string/DOMDocument::loadXML` with `LIBXML_NOENT`/`LIBXML_DTDLOAD`; `libxml_disable_entity_loader(false)` on PHP < 8 |
| Redirect | `header("Location: " . $x)`, `redirect($request->url)`, `redirect()->away($x)`, `wp_redirect($x)` (use `wp_safe_redirect`) |
| Auth logic | Loose `==` with hashes/tokens (`"0e123" == "0e456"` is true), `strcmp($_POST['p'], $pw) == 0` (array → NULL), `in_array` without strict, `md5($password)` storage |

## Sanitizers / safe APIs
- SQL: PDO/mysqli prepared statements with bound params; Eloquent/Query Builder `where('col', $v)`, `whereIn`; `$wpdb->prepare`; identifier allow-list for `orderBy`. Note `DB::select('... ?', [$v])` is safe.
- Command: `escapeshellarg` per argument (not `escapeshellcmd` alone), Symfony `new Process([...])` array form.
- HTML: Blade `{{ }}`, Twig autoescape, `htmlspecialchars($x, ENT_QUOTES, 'UTF-8')`, HTML Purifier for rich text, WP `esc_*` / `wp_kses`.
- Path: `basename()`, `realpath()` + `str_starts_with($real, $base . DIRECTORY_SEPARATOR)`.
- Comparison: `hash_equals`, `password_hash`/`password_verify`, `===`.
- Deserialization: `json_decode`; `unserialize($x, ['allowed_classes' => false])`.
- Laravel validation `'id' => 'integer'`, `'sort' => 'in:name,date'` constrains: valid for the matching sink.

## Framework notes
- Laravel: `APP_DEBUG=true` in production `.env` (Ignition RCE on old versions, info leak), `APP_KEY` committed, `$guarded = []` / `Model::unguard()`, `$request->all()` into `create/update/fill`, routes missing `auth`/`can:` middleware, `VerifyCsrfToken::$except` entries, `Route::any` on state-changing actions, signed URL checks missing, `Storage::disk('public')` for private files.
- Symfony: `access_control` gaps, missing `#[IsGranted]`, `APP_ENV=dev` + profiler exposed (`/_profiler`), `APP_SECRET` committed.
- WordPress: AJAX and REST handlers need `current_user_can` + `check_ajax_referer`/`wp_verify_nonce`; `permission_callback => '__return_true'`.
- `rand/mt_rand/uniqid` for tokens → `random_bytes`/`random_int`. `md5/sha1` passwords → `password_hash`.
- `display_errors=On`, `phpinfo()`, `var_dump`/`dd()` left in code, `.env` reachable in webroot.
- File uploads: check extension **and** content, block `.php/.phtml/.phar/.htaccess`, store outside `public/`.
