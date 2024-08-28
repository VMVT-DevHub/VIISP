using Microsoft.Extensions.Configuration;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml.Serialization;
using System.Xml;
using VIISP;
using VIISP.App;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography.Xml;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
	.AddJsonFile("secrets.json", optional: true, reloadOnChange: true); 

builder.Services.ConfigureHttpJsonOptions(a => {
	a.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
	a.SerializerOptions.WriteIndented = false;
	a.SerializerOptions.Converters.Add(new CustomDateTimeConverter());
	a.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});


var app = builder.Build();

var cfg = new Configuration(app);


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
			if (dt.Error is null) await ctx.Response.WriteAsJsonAsync(new DataResponse_v1(dt).Login(cfg.ConnStr, i.Name, i.ShowAk), ct);
			else { ctx.Response.StatusCode = StatusCodes.Status400BadRequest; await ctx.Response.WriteAsJsonAsync(dt.Error, ct); }
		}
		else ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
	}
	else ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
});






app.MapGet("/auth/v2/{key}", async (HttpContext ctx, string key, CancellationToken ct) => {
	if(ctx.GetCfg(out var i) && i.Cfg is not null) {
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
}).GetTokenV2(cfg);

app.MapGet("/auth/v2/{key}/{token}", async (HttpContext ctx, string key, Guid token, CancellationToken ct) => {
	if (ctx.GetCfg(out var i) && i.Cfg is not null) {
		if (cfg.GetToken(token, out var j) && j.ExpiresOn > DateTime.UtcNow) {
			var dt = await new AuthenticationDataRequest(j.Ticket) { Pid = i.Cfg.Pid }.Execute(i.Cfg, ct);
			if (cfg.Debug) { Debug.Print(dt); }
			if (dt.Error is null) await ctx.Response.WriteAsJsonAsync(new DataResponse_v2(dt).Login(cfg.ConnStr, i.Name, i.ShowAk), ct);
			else { ctx.Response.StatusCode = StatusCodes.Status400BadRequest; await ctx.Response.WriteAsJsonAsync(dt.Error, ct); }
		}
		else ctx.Response.StatusCode = StatusCodes.Status404NotFound;
	}
}).GetTokenV2(cfg);

app.MapPost("/auth/v2/{key}/user", async (HttpContext ctx, string key, [FromBody] UserData user, CancellationToken ct) => {
	if (ctx.GetCfg(out var i) && i.Cfg is not null) {	
		if (user.AK>1e10 && user.AK<1e11) {
			if (cfg.Debug) { Debug.Print(user); }
			var usr = VIISP.App.DBExec.CreateUser(user, cfg.ConnStr, i.Name, i.ShowAk);
			if (usr?.Id is not null) await ctx.Response.WriteAsJsonAsync(usr, ct);
			else ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
		}
		else ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
	}
}).GetTokenV2(cfg);

app.MapGet("/auth/v2/{key}/user/{user}", async (HttpContext ctx, string key, string user, CancellationToken ct) => {
	if (ctx.GetCfg(out var i) && i.GetUser && i.Cfg is not null) {
		UserData? usr = null;
		if (Guid.TryParse(user, out var ui)) usr = ui.GetUser(cfg.ConnStr, i.Name, i.ShowAk);
		else if (long.TryParse(user, out var ak)) usr = ak.GetUser(cfg.ConnStr, i.Name, i.ShowAk);

		if (usr is not null) await ctx.Response.WriteAsJsonAsync(usr, ct);
		else ctx.Response.StatusCode = StatusCodes.Status404NotFound;
	}
	else ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
}).GetTokenV2(cfg);

app.Run();


