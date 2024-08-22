using Microsoft.Extensions.Configuration;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml.Serialization;
using System.Xml;
using VIISP;
using VIISP.App;
using static System.Net.Mime.MediaTypeNames;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddUserSecrets<Program>(true);

builder.Services.ConfigureHttpJsonOptions(a => {
	a.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
	a.SerializerOptions.WriteIndented = false;
	a.SerializerOptions.Converters.Add(new CustomDateTimeConverter());
	a.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});


var app = builder.Build();

var cfg = new Configuration(app);

Console.WriteLine(Guid.NewGuid());


app.Map("/auth/v1/{key}/sign", async (HttpContext ctx, string key, CancellationToken ct) => {
	if (cfg.GetCfg(key, out var i) && i.Cfg is not null) {
		if (i.AllowV1) {
			var dt = await new AuthenticationRequest() { Pid = i.Cfg.Pid ,PostbackUrl=i.Cfg.PostbackUrl }.Execute(i.Cfg, ct);
			if (dt.Error is null) await ctx.Response.WriteAsJsonAsync(new TicketResponse_v1() { Ticket = dt.Ticket, Url = i.Cfg.TicketUrl + dt.Ticket, Host = i.Cfg.TicketUrl?.Split('?')[0] }, ct);
			else { ctx.Response.StatusCode = StatusCodes.Status400BadRequest; await ctx.Response.WriteAsJsonAsync(dt.Error, ct); }
		}
		else ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
	}
	else ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
});

app.Map("/auth/v1/{key}/data", async (HttpContext ctx, string key, Guid ticket, CancellationToken ct) => {
	if (cfg.GetCfg(key, out var i) && i.Cfg is not null) {
		if (i.AllowV1) {
			var dt = await new AuthenticationDataRequest(ticket) { Pid = i.Cfg.Pid }.Execute(i.Cfg, ct);
			if (cfg.Debug) { Debug.Print(dt); }
			if (dt.Error is null) await ctx.Response.WriteAsJsonAsync(new DataResponse(dt).Login(cfg.ConnStr, i.Name, i.ShowAk), ct);
			else { ctx.Response.StatusCode = StatusCodes.Status400BadRequest; await ctx.Response.WriteAsJsonAsync(dt.Error, ct); }
		}
		else ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
	}
	else ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
});



app.MapGet("/auth/v2/{key}", async (HttpContext ctx, string key, CancellationToken ct) => {
	if (cfg.GetCfg(key, out var i) && i.Cfg is not null) {
		var pbu = i.Cfg.PostbackUrl ?? ""; var tkn = Guid.NewGuid();
		var dt = await new AuthenticationRequest() {
			Pid = i.Cfg.Pid,
			PostbackUrl = $"{pbu}{(pbu.Contains('?') ? "&" : "?")}token={tkn}"
		}.Execute(i.Cfg, ct);
		if (dt.Error is null) await ctx.Response.WriteAsJsonAsync(cfg.SetToken(i, dt, tkn), ct);
		else {
			ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
			await ctx.Response.WriteAsJsonAsync(dt.Error, ct);
		}
	}
	else ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
});

app.MapGet("/auth/v2/{key}/{token}", async (HttpContext ctx, string key, Guid token, CancellationToken ct) => {
	if (cfg.GetCfg(key, out var i) && i.Cfg is not null) {
		if (cfg.GetToken(token, out var j) && j.ExpiresOn > DateTime.UtcNow) {
			var dt = await new AuthenticationDataRequest(j.Ticket) { Pid = i.Cfg.Pid }.Execute(i.Cfg, ct);
			if (cfg.Debug) { Debug.Print(dt); }
			if (dt.Error is null) await ctx.Response.WriteAsJsonAsync(new DataResponse(dt).Login(cfg.ConnStr, i.Name, i.ShowAk), ct);
			else { ctx.Response.StatusCode = StatusCodes.Status400BadRequest; await ctx.Response.WriteAsJsonAsync(dt.Error, ct); }
		}
		else ctx.Response.StatusCode = StatusCodes.Status404NotFound;
	}
	else ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
});

app.Run();




public class CustomDateTimeConverter : JsonConverter<DateTime> {
	public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) => DateTime.TryParse(reader.GetString(), out var dt) ? dt : default;
	public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options) => writer.WriteStringValue(value.ToString("yyyy-MM-ddTHH:mm:ssZ"));
}

public static class Debug {
	private static readonly object writeLock = new();
	public static void Print(object data) {
		var file = $"debug/{DateTime.UtcNow:yyyyy-MM-dd}.log";
		if (!File.Exists(file)) { File.Create(file).Close(); }

		lock (writeLock) {
			using var writer = File.AppendText(file);
			writer.WriteLine($"{DateTime.UtcNow} {JsonSerializer.Serialize(data)}");
		}
	}
}