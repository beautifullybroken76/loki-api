using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.SqlClient;
using Microsoft.IdentityModel.Tokens;

static bool ValidAdventureId(string? id) =>
    id is { Length: >= 1 and <= 60 } &&
    id.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;
var conn = config.GetConnectionString("Loki")
    ?? throw new InvalidOperationException(
        "Missing Loki database connection string.");
var jwtKey = config["Jwt:SigningKey"]
    ?? throw new InvalidOperationException(
        "Missing JWT signing key.");
if (string.IsNullOrWhiteSpace(conn) || Encoding.UTF8.GetByteCount(jwtKey) < 32)
    throw new InvalidOperationException("Set ConnectionStrings:Loki and Jwt:SigningKey (at least 32 UTF-8 bytes) in secure hosting configuration.");
var allowed = config.GetSection("AllowedOrigins").Get<string[]>() ?? [];
builder.Services.AddCors(o => o.AddPolicy("Game", p => p.WithOrigins(allowed).AllowAnyHeader().AllowAnyMethod()));
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o => {
    o.RequireHttpsMetadata = true;
    o.TokenValidationParameters = new TokenValidationParameters {
        ValidateIssuer = true, ValidIssuer = config["Jwt:Issuer"],
        ValidateAudience = true, ValidAudience = config["Jwt:Audience"],
        ValidateIssuerSigningKey = true, IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
        ValidateLifetime = true, ClockSkew = TimeSpan.FromMinutes(1)
    };
});
builder.Services.AddAuthorization();
builder.Services.AddSingleton<IPasswordHasher<Player>, PasswordHasher<Player>>();
builder.Services.AddRateLimiter(o => {
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddPolicy("auth", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown", _ => new FixedWindowRateLimiterOptions {
            PermitLimit = 12, Window = TimeSpan.FromMinutes(5), QueueLimit = 0, AutoReplenishment = true
        }));
});
var app = builder.Build();
app.UseHttpsRedirection();
app.UseCors("Game");
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/api/health", () => Results.Ok(new { status = "ok" }));

//app.MapGet("/api/health/password-check", () =>
//{
//    var cs = new SqlConnectionStringBuilder(conn);

//    return Results.Ok(new
//    {
//        passwordPresent = !string.IsNullOrEmpty(cs.Password),
//        passwordLength = cs.Password.Length
//    });
//});

//app.MapGet("/api/health/db", async () =>
//{
//    var step = "Opening SQL connection";

//    try
//    {
//        await using var db = new SqlConnection(conn);
//        await db.OpenAsync();

//        step = "Querying LokiPlayers table";

//        await using var cmd = new SqlCommand(
//            "SELECT COUNT(*) FROM dbo.LokiPlayers", db);

//        var count = await cmd.ExecuteScalarAsync();

//        return Results.Ok(new
//        {
//            status = "ok",
//            database = "connected",
//            playerCount = Convert.ToInt32(count)
//        });
//    }
//    catch (SqlException ex)
//    {
//        app.Logger.LogError(ex,
//            "SQL connection failed. Error number: {Number}",
//            ex.Number);

//        return Results.Problem(
//            title: "SQL connection failed",
//            detail: $"SQL error number: {ex.Number}",
//            statusCode: 500);
//    }
//    catch (Exception ex)
//    {
//        app.Logger.LogError(ex, "Database connection failed");

//        return Results.Problem(
//            title: "Database connection failed",
//            statusCode: 500);
//    }
//});
app.MapPost("/api/auth/register", async (Credentials request, IPasswordHasher<Player> hasher) => {
    var name = request.UserName?.Trim() ?? "";
    if (name.Length < 3 || name.Length > 60 || !name.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.'))
        return Results.BadRequest(new { error = "Username must be 3–60 letters, numbers, dots, hyphens or underscores." });
    if (request.Password is null || request.Password.Length < 12 || request.Password.Length > 256)
        return Results.BadRequest(new { error = "Password must be 12–256 characters." });
    var player = new Player(Guid.NewGuid(), name, "");
    var hash = hasher.HashPassword(player, request.Password);
    try {
        await using var db = new SqlConnection(conn); await db.OpenAsync();
        await using var cmd = new SqlCommand("INSERT INTO dbo.LokiPlayers(PlayerId,UserName,NormalizedUserName,PasswordHash) VALUES (@id,@name,@norm,@hash)", db);
        cmd.Parameters.AddWithValue("@id", player.Id);
        cmd.Parameters.AddWithValue("@name", name);
        cmd.Parameters.AddWithValue("@norm", name.ToUpperInvariant());
        cmd.Parameters.AddWithValue("@hash", hash);
        await cmd.ExecuteNonQueryAsync();
        return Results.Ok(new { token = Token(player), userName = name });
    } catch (SqlException ex) when (ex.Number is 2601 or 2627) { return Results.Conflict(new { error = "Username already taken." }); }
}).RequireRateLimiting("auth");

app.MapPost("/api/auth/login", async (Credentials request, IPasswordHasher<Player> hasher) => {
    var name = request.UserName?.Trim() ?? "";
    await using var db = new SqlConnection(conn); await db.OpenAsync();
    await using var cmd = new SqlCommand("SELECT PlayerId,UserName,PasswordHash FROM dbo.LokiPlayers WHERE NormalizedUserName=@name", db);
    cmd.Parameters.AddWithValue("@name", name.ToUpperInvariant());
    await using var r = await cmd.ExecuteReaderAsync();
    if (!await r.ReadAsync()) return Results.Unauthorized();
    var player = new Player(r.GetGuid(0), r.GetString(1), r.GetString(2));
    var check = hasher.VerifyHashedPassword(player, player.PasswordHash, request.Password ?? "");
    if (check == PasswordVerificationResult.Failed) return Results.Unauthorized();
    return Results.Ok(new { token = Token(player), userName = player.UserName });
}).RequireRateLimiting("auth");

app.MapGet("/api/progress", async (ClaimsPrincipal user) => {
    var id = Guid.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)!);
    await using var db = new SqlConnection(conn); await db.OpenAsync();
    await using var cmd = new SqlCommand("SELECT SaveJson,Revision,UpdatedUtc FROM dbo.LokiProgress WHERE PlayerId=@id", db);
    cmd.Parameters.AddWithValue("@id", id);
    await using var r = await cmd.ExecuteReaderAsync();
    if (!await r.ReadAsync()) return Results.Ok(new { revision = 0, save = (JsonElement?)null });
    return Results.Ok(new { revision = r.GetInt32(1), save = JsonDocument.Parse(r.GetString(0)).RootElement.Clone(), updatedUtc = r.GetDateTime(2) });
}).RequireAuthorization();

app.MapPut("/api/progress", async (ClaimsPrincipal user, SaveRequest req) => {
    if (req.Revision < 0 || req.Save.ValueKind != JsonValueKind.Object) return Results.BadRequest(new { error = "Invalid save or revision." });
    var json = req.Save.GetRawText();
    if (Encoding.UTF8.GetByteCount(json) > 100_000) return Results.BadRequest(new { error = "Save exceeds 100 KB." });
    var id = Guid.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)!);
    await using var db = new SqlConnection(conn); await db.OpenAsync();
    await using var transaction = (SqlTransaction)await db.BeginTransactionAsync(System.Data.IsolationLevel.Serializable);
    await using var get = new SqlCommand("SELECT Revision FROM dbo.LokiProgress WITH (UPDLOCK,HOLDLOCK) WHERE PlayerId=@id", db, transaction);
    get.Parameters.AddWithValue("@id", id);
    var value = await get.ExecuteScalarAsync();
    var current = value is null ? 0 : Convert.ToInt32(value);
    if (current != req.Revision) { await transaction.RollbackAsync(); return Results.Conflict(new { error = "Cloud save changed on another device.", revision = current }); }
    await using var write = new SqlCommand(current == 0
        ? "INSERT INTO dbo.LokiProgress(PlayerId,SaveJson,Revision) VALUES(@id,@json,1)"
        : "UPDATE dbo.LokiProgress SET SaveJson=@json,Revision=Revision+1,UpdatedUtc=SYSUTCDATETIME() WHERE PlayerId=@id", db, transaction);
    write.Parameters.AddWithValue("@id", id);
    write.Parameters.AddWithValue("@json", json);
    await write.ExecuteNonQueryAsync();
    await transaction.CommitAsync();
    return Results.Ok(new { revision = current + 1 });
}).RequireAuthorization();

//if (args.Contains("--reset-password"))
//{
//    const string userName = "ppickett";

//    Console.Write("Enter new password: ");
//    var newPassword = ReadPassword();

//    if (newPassword.Length < 12 || newPassword.Length > 256)
//        throw new Exception("Password must be 12–256 characters.");

//    await using var db = new SqlConnection(conn);
//    await db.OpenAsync();

//    // Retrieve the existing player ID.
//    Guid playerId;

//    await using (var find = new SqlCommand(
//        "SELECT PlayerId FROM dbo.LokiPlayers WHERE NormalizedUserName = @name", db))
//    {
//        find.Parameters.AddWithValue("@name", userName.ToUpperInvariant());

//        var result = await find.ExecuteScalarAsync();

//        if (result is null)
//            throw new Exception($"Player '{userName}' not found.");

//        playerId = (Guid)result;
//    }

//    var player = new Player(playerId, userName, "");
//    var hasher = app.Services.GetRequiredService<IPasswordHasher<Player>>();
//    var hash = hasher.HashPassword(player, newPassword);

//    await using (var update = new SqlCommand(
//        "UPDATE dbo.LokiPlayers SET PasswordHash = @hash WHERE PlayerId = @id", db))
//    {
//        update.Parameters.AddWithValue("@hash", hash);
//        update.Parameters.AddWithValue("@id", playerId);

//        await update.ExecuteNonQueryAsync();
//    }

//    Console.WriteLine("Password reset successfully.");
//    return;
//}

//static string ReadPassword()
//{
//    var password = new System.Text.StringBuilder();

//    while (true)
//    {
//        var key = Console.ReadKey(intercept: true);

//        if (key.Key == ConsoleKey.Enter)
//        {
//            Console.WriteLine();
//            break;
//        }

//        if (key.Key == ConsoleKey.Backspace)
//        {
//            if (password.Length > 0)
//                password.Length--;

//            continue;
//        }

//        if (!char.IsControl(key.KeyChar))
//            password.Append(key.KeyChar);
//    }

//    return password.ToString();
//}

// Password recovery using a high-entropy, one-time code. No email address required.
// Recovery codes are issued only to authenticated players; the hash alone is stored.
app.MapPost("/api/auth/recovery-code", async (ClaimsPrincipal user) => {
    var playerId = Guid.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)!);
    var secret = RandomNumberGenerator.GetBytes(32);
    var codeText = Convert.ToHexString(secret); // 64 uppercase hex characters, shown once
    var codeHash = SHA256.HashData(Encoding.UTF8.GetBytes(codeText));
    await using var db = new SqlConnection(conn);
    await db.OpenAsync();
    await using var cmd = new SqlCommand(@"
        UPDATE dbo.PlayerRecoveryCodes SET CodeHash=@hash,CreatedUtc=SYSUTCDATETIME()
        WHERE PlayerId=@id;
        IF @@ROWCOUNT=0
            INSERT INTO dbo.PlayerRecoveryCodes(PlayerId,CodeHash) VALUES(@id,@hash);", db);
    cmd.Parameters.Add("@id", System.Data.SqlDbType.UniqueIdentifier).Value = playerId;
    cmd.Parameters.Add("@hash", System.Data.SqlDbType.Binary, 32).Value = codeHash;
    await cmd.ExecuteNonQueryAsync();
    return Results.Ok(new { recoveryCode = codeText, message = "Save this code now. It will not be displayed again." });
}).RequireAuthorization().RequireRateLimiting("auth");

app.MapPost("/api/auth/reset-password", async (PasswordResetRequest req, IPasswordHasher<Player> hasher) => {
    var name = req.UserName?.Trim() ?? "";
    var codeText = (req.RecoveryCode ?? "").Trim().ToUpperInvariant();
    if (name.Length is < 3 or > 60 || req.NewPassword is null || req.NewPassword.Length is < 12 or > 256 ||
        codeText.Length != 64 || !codeText.All(Uri.IsHexDigit))
        return Results.BadRequest(new { error = "Invalid reset request. Password must be 12–256 characters." });
    var hash = SHA256.HashData(Encoding.UTF8.GetBytes(codeText));
    await using var db = new SqlConnection(conn);
    await db.OpenAsync();
    await using var tx = (SqlTransaction)await db.BeginTransactionAsync(System.Data.IsolationLevel.Serializable);
    await using var find = new SqlCommand(@"
        SELECT p.PlayerId,p.UserName,p.PasswordHash,r.CodeHash
        FROM dbo.LokiPlayers p WITH (UPDLOCK,HOLDLOCK)
        LEFT JOIN dbo.PlayerRecoveryCodes r WITH (UPDLOCK,HOLDLOCK) ON r.PlayerId=p.PlayerId
        WHERE p.NormalizedUserName=@name", db, tx);
    find.Parameters.Add("@name", System.Data.SqlDbType.NVarChar, 60).Value = name.ToUpperInvariant();
    Guid playerId = default;
    string? actualName = null;
    byte[]? storedHash = null;
    await using (var reader = await find.ExecuteReaderAsync()) {
        if (await reader.ReadAsync()) {
            playerId = reader.GetGuid(0);
            actualName = reader.GetString(1);
            if (!reader.IsDBNull(3)) storedHash = (byte[])reader.GetValue(3);
        }
    }
    if (storedHash is null || !CryptographicOperations.FixedTimeEquals(hash, storedHash)) {
        await tx.RollbackAsync();
        return Results.BadRequest(new { error = "Invalid username or recovery code." });
    }
    var player = new Player(playerId, actualName!, "");
    var passwordHash = hasher.HashPassword(player, req.NewPassword);
    await using var update = new SqlCommand(@"
        UPDATE dbo.LokiPlayers SET PasswordHash=@hash WHERE PlayerId=@id;
        DELETE FROM dbo.PlayerRecoveryCodes WHERE PlayerId=@id;", db, tx);
    update.Parameters.Add("@id", System.Data.SqlDbType.UniqueIdentifier).Value = playerId;
    update.Parameters.Add("@hash", System.Data.SqlDbType.NVarChar, -1).Value = passwordHash;
    await update.ExecuteNonQueryAsync();
    await tx.CommitAsync();
    return Results.Ok(new { message = "Password reset. Your recovery code has been used; generate a new one after signing in." });
}).RequireRateLimiting("auth");

// Adventure-aware progress endpoints. Existing /api/progress remains unchanged.
// "loki" deliberately uses the existing LokiProgress table so there is one
// canonical Loki save and no copy/migration conflicts.
app.MapGet("/api/adventures/{adventureId}/progress", async (string adventureId, ClaimsPrincipal user) => {
    if (!ValidAdventureId(adventureId)) return Results.BadRequest(new { error = "Invalid adventure ID." });
    var id = Guid.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)!);
    var isLoki = adventureId.Equals("loki", StringComparison.OrdinalIgnoreCase);
    await using var db = new SqlConnection(conn); await db.OpenAsync();
    await using var cmd = new SqlCommand(isLoki
        ? "SELECT SaveJson,Revision,UpdatedUtc FROM dbo.LokiProgress WHERE PlayerId=@id"
        : "SELECT SaveJson,Revision,UpdatedUtc FROM dbo.AdventureProgress WHERE PlayerId=@id AND AdventureId=@adventure", db);
    cmd.Parameters.AddWithValue("@id", id);
    if (!isLoki) cmd.Parameters.AddWithValue("@adventure", adventureId.ToLowerInvariant());
    await using var r = await cmd.ExecuteReaderAsync();
    if (!await r.ReadAsync()) return Results.Ok(new { revision = 0, save = (JsonElement?)null });
    return Results.Ok(new { revision = r.GetInt32(1), save = JsonDocument.Parse(r.GetString(0)).RootElement.Clone(), updatedUtc = r.GetDateTime(2) });
}).RequireAuthorization();

app.MapPut("/api/adventures/{adventureId}/progress", async (string adventureId, ClaimsPrincipal user, SaveRequest req) => {
    if (!ValidAdventureId(adventureId)) return Results.BadRequest(new { error = "Invalid adventure ID." });
    if (req.Revision < 0 || req.Save.ValueKind != JsonValueKind.Object)
        return Results.BadRequest(new { error = "Invalid save or revision." });
    var json = req.Save.GetRawText();
    if (Encoding.UTF8.GetByteCount(json) > 100_000)
        return Results.BadRequest(new { error = "Save exceeds 100 KB." });
    var id = Guid.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)!);
    var isLoki = adventureId.Equals("loki", StringComparison.OrdinalIgnoreCase);
    var table = isLoki ? "dbo.LokiProgress" : "dbo.AdventureProgress"; // hardcoded, never user input
    await using var db = new SqlConnection(conn); await db.OpenAsync();
    await using var transaction = (SqlTransaction)await db.BeginTransactionAsync(System.Data.IsolationLevel.Serializable);
    var where = isLoki ? "PlayerId=@id" : "PlayerId=@id AND AdventureId=@adventure";
    await using var get = new SqlCommand($"SELECT Revision FROM {table} WITH (UPDLOCK,HOLDLOCK) WHERE {where}", db, transaction);
    get.Parameters.AddWithValue("@id", id);
    if (!isLoki) get.Parameters.AddWithValue("@adventure", adventureId.ToLowerInvariant());
    var value = await get.ExecuteScalarAsync();
    var current = value is null ? 0 : Convert.ToInt32(value);
    if (current != req.Revision) {
        await transaction.RollbackAsync();
        return Results.Conflict(new { error = "Cloud save changed on another device.", revision = current });
    }
    var insertSql = isLoki
        ? "INSERT INTO dbo.LokiProgress(PlayerId,SaveJson,Revision) VALUES(@id,@json,1)"
        : "INSERT INTO dbo.AdventureProgress(PlayerId,AdventureId,SaveJson,Revision) VALUES(@id,@adventure,@json,1)";
    var updateSql = $"UPDATE {table} SET SaveJson=@json,Revision=Revision+1,UpdatedUtc=SYSUTCDATETIME() WHERE {where}";
    await using var write = new SqlCommand(current == 0 ? insertSql : updateSql, db, transaction);
    write.Parameters.AddWithValue("@id", id);
    write.Parameters.AddWithValue("@json", json);
    if (!isLoki) write.Parameters.AddWithValue("@adventure", adventureId.ToLowerInvariant());
    await write.ExecuteNonQueryAsync();
    await transaction.CommitAsync();
    return Results.Ok(new { revision = current + 1 });
}).RequireAuthorization();

app.Run();

string Token(Player player) {
    var claims = new[] { new Claim(ClaimTypes.NameIdentifier, player.Id.ToString()), new Claim(ClaimTypes.Name, player.UserName) };
    var token = new JwtSecurityToken(config["Jwt:Issuer"], config["Jwt:Audience"], claims,
        expires: DateTime.UtcNow.AddHours(12), signingCredentials: new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)), SecurityAlgorithms.HmacSha256));
    return new JwtSecurityTokenHandler().WriteToken(token);
}
record Player(Guid Id, string UserName, string PasswordHash);
record Credentials(string? UserName, string? Password);
record SaveRequest(int Revision, JsonElement Save);

record PasswordResetRequest(string? UserName, string? RecoveryCode, string? NewPassword);
