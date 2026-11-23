# C# / .NET (ASP.NET Core, MVC, Web API, Razor Pages, Blazor, Web Forms, EF Core, Dapper)

## Sources
- `Request.Query/Form/Cookies/Headers/Body/RouteValues/Path/QueryString`, `HttpContext.Request`, legacy `Request.QueryString/Params/Form/ServerVariables`
- Action parameters (bound from route/query/body by default), `[FromQuery] [FromBody] [FromRoute] [FromForm] [FromHeader]`, model-bound classes, `IFormFile.FileName`
- Razor Pages bound properties (`[BindProperty]`), Blazor component `[Parameter]`/`[SupplyParameterFromQuery]`, SignalR hub method args, gRPC messages, Azure Functions `HttpRequest`
- `Environment.GetCommandLineArgs`, `Console.ReadLine`

## Sinks
| Class | Sinks |
|---|---|
| SQL | `new SqlCommand(sql + x)`, `cmd.CommandText = $"... {x}"`, EF Core `FromSqlRaw($"...{x}")`/`ExecuteSqlRaw(... + x)`/`SqlQueryRaw` (note: `FromSqlInterpolated`/`FromSql($"...")` **are** parameterized), Dapper `Query($"... {x}")` / concat, `string.Format` SQL, LINQ Dynamic `Where(userString)` |
| Command | `Process.Start(user)`, `ProcessStartInfo { FileName = "cmd.exe", Arguments = "/c " + x }` |
| Path | `File.*`, `FileStream`, `Path.Combine(base, user)` (absolute second arg overrides base!), `PhysicalFile(user)`, `ZipFile.ExtractToDirectory` / `entry.FullName` (zip slip), `Server.MapPath(user)` |
| SSRF | `HttpClient.GetAsync/PostAsync/SendAsync(user)`, `WebRequest.Create(user)`, `WebClient.DownloadString(user)`, `new Uri(user)` passed to a client |
| XSS | `Html.Raw(user)`, `@Html.Raw`, `new HtmlString(user)`, `(MarkupString)user` in Blazor, `Response.Write(user)`, `Content(user, "text/html")`, Web Forms `<%= %>` (unencoded; `<%: %>` encodes), `[ValidateInput(false)]`, `[AllowHtml]` |
| Deserialization | `BinaryFormatter` (obsolete, unsafe), `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter`, Json.NET `TypeNameHandling` ≠ `None`, `JavaScriptSerializer` with `SimpleTypeResolver`, `XmlSerializer(Type.GetType(user))`, `DataContractSerializer` with known-type resolver from input; ViewState without MAC |
| XXE | `XmlDocument` with `XmlResolver` set (unsafe default before .NET 4.5.2), `XmlTextReader` (unsafe default before 4.5.2), `XmlReaderSettings { DtdProcessing = Parse }` |
| Redirect | `Redirect(user)`, `RedirectPermanent(user)`, `Response.Redirect(user)` → use `LocalRedirect` / `Url.IsLocalUrl` |
| LDAP | `DirectorySearcher.Filter = "(cn=" + x + ")"` |
| Reflection | `Type.GetType(user)`, `Activator.CreateInstance(user)`, `Assembly.Load(user)` |

## Sanitizers / safe APIs
- SQL: `SqlParameter`/`cmd.Parameters.AddWithValue`, Dapper anonymous parameters `new { id }`, EF LINQ queries, `FromSqlInterpolated`.
- HTML: Razor `@x` (auto-encoded), `HtmlEncoder.Default.Encode`, HtmlSanitizer (Ganss.Xss) for rich content.
- Path: `Path.GetFileName`, `Path.GetFullPath(p).StartsWith(Path.GetFullPath(base) + Path.DirectorySeparatorChar)`.
- Redirect: `LocalRedirect`, `Url.IsLocalUrl`.
- Deserialization: `System.Text.Json` (no polymorphic type info from input), Json.NET `TypeNameHandling.None` or a `SerializationBinder` allow-list.
- Validation: DataAnnotations (`[Range]`, `[RegularExpression]`) + `ModelState.IsValid` checked.

## Framework notes
- Missing `[Authorize]` on controllers/actions or a missing global `FallbackPolicy`; `[AllowAnonymous]` on sensitive actions; policy checks with only roles where resource ownership is needed (IDOR).
- Antiforgery: MVC needs `[ValidateAntiForgeryToken]` or `AutoValidateAntiforgeryToken`; `[IgnoreAntiforgeryToken]` on POST actions with cookie auth.
- CORS `AllowAnyOrigin()` with `AllowCredentials()` (not allowed, but `SetIsOriginAllowed(_ => true)` + credentials is the dangerous equivalent).
- `UseDeveloperExceptionPage()` outside `IsDevelopment()`; `web.config` `customErrors mode="Off"`, `debug="true"`, `<httpCookies requireSSL="false">`.
- Secrets: connection strings with passwords in `appsettings.json` (use User Secrets / Key Vault / env vars).
- Mass assignment / overposting: binding EF entities directly; use DTOs/view models or `[Bind("A,B")]`.
- Crypto: `MD5`/`SHA1` for passwords → `PasswordHasher<T>`/`Rfc2898DeriveBytes.Pbkdf2` (≥ 600k iterations, SHA256); `new Random()` → `RandomNumberGenerator`; `CipherMode.ECB`; `ServerCertificateCustomValidationCallback = (...) => true`.
