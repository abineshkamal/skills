# Ruby (Rails, Sinatra, Rack, Grape)

## Sources
- `params[...]`, `params.require(...).permit(...)` (permitted values are still tainted), `request.params/query_string/body/raw_post/headers/env/referer/host`, `cookies[...]`, `session` (when the cookie store secret is weak or leaked), uploaded `original_filename`, ActionCable `data`, Sidekiq job args, `ARGV`, `gets`

## Sinks
| Class | Sinks |
|---|---|
| SQL | `where("name = '#{x}'")`, `where("... #{x}")`, `order(params[:sort])`, `pluck(user)`, `select(user)`, `group/having/joins/from/lock(user)`, `find_by_sql("...#{x}")`, `connection.execute/exec_query/select_all("...#{x}")`, `exists?(params[:id])` (old Rails), `update_all("...#{x}")`, `calculate(:sum, user)`, `Arel.sql(user)` |
| Command | `system("cmd #{x}")`, `exec`, `` `cmd #{x}` ``, `%x()`, `IO.popen`, `Open3.*` with a single string, `Kernel.open("|cmd")`, `open(user)` (Kernel#open runs a command when the string starts with `\|`), `spawn` |
| Code | `eval`, `instance_eval/class_eval/module_eval(user)`, `send/public_send(params[:method])`, `constantize/safe_constantize(user)`, `Object.const_get(user)`, `ERB.new(user).result` (SSTI) |
| Deserialization | `Marshal.load`, `YAML.load` (unsafe before Psych 4 / Ruby 3.1; use `safe_load`), `YAML.unsafe_load`, `Oj.load` (default `:object` mode), `JSON.load` (creates additions), `ActiveSupport::MessageVerifier` with leaked secret |
| XSS | `html_safe`, `raw(user)`, `<%== user %>`, `render inline: user` (also SSTI), `render html: user.html_safe`, `content_tag` with unsanitized attributes, `link_to user_text, user_url` (`javascript:` URL), `safe_concat` |
| Path | `File.open/read/write(user)`, `send_file(user)`, `render file: params[:x]`, `render template: user`, `Dir.glob(user)`, `FileUtils.*`, `Rails.root.join(user)` (absolute paths win) |
| Redirect | `redirect_to params[:url]`, `redirect_to request.referer`, `allow_other_host: true` (Rails 7) |
| SSRF | `Net::HTTP.get(URI(user))`, `URI.open(user)`, `open-uri`, `HTTParty`, `Faraday`, `RestClient`, `Down` |
| Mass assignment | `params.permit!`, `to_unsafe_h`, `Model.new(params[:model])` without `permit`, permitting `:role`, `:admin`, `:account_id` |

## Sanitizers / safe APIs
- SQL: hash conditions `where(name: x)`, placeholders `where("name = ?", x)`, `sanitize_sql_array`, `sanitize_sql_like`, `order(Arel.sql(...))` **only** with allow-listed columns, `connection.quote`.
- Command: `system("cmd", arg1, arg2)` (multi-arg form, no shell), `Shellwords.escape`.
- HTML: ERB `<%= %>` auto-escapes in Rails, `sanitize(user, tags: [...])`, `strip_tags`, `ERB::Util.h`.
- Path: `File.basename`, `File.expand_path(p, base).start_with?(base + "/")`.
- Redirect: `redirect_to url_from(params[:url]) || root_path` (Rails 7), `only_path: true`.
- YAML: `YAML.safe_load(x, permitted_classes: [...])`.

## Framework notes
- `skip_before_action :verify_authenticity_token`, `protect_from_forgery with: :null_session` on cookie-auth controllers.
- `skip_before_action :authenticate_user!` on sensitive actions; missing Pundit/CanCan `authorize` calls (`verify_authorized` not enforced); `Model.find(params[:id])` instead of `current_user.models.find(...)` (IDOR).
- `config/secrets.yml` / `config/master.key` / `secret_key_base` committed; `credentials.yml.enc` is fine without its key.
- `config.force_ssl = false` in production, `consider_all_requests_local = true` in production, `config.hosts.clear`.
- `Digest::MD5`/`SHA1` for passwords → `has_secure_password` (bcrypt); `rand`/`Random` for tokens → `SecureRandom`.
- Brakeman-class checks: dynamic `render`, unsafe `link_to`, `mail_to`, `select` with user-provided options, `validates_format_of` using `^…$` (multiline anchors; use `\A…\z`).
