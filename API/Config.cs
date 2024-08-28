using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;
using System.Text.Json;
using static System.Runtime.InteropServices.JavaScript.JSType;
using Microsoft.AspNetCore.DataProtection.KeyManagement;

namespace VIISP.App;

public class Configuration {
	private WebApplication App { get; }
	public string ConnStr { get; set; }
	public DateTime NextReload { get; private set; }
	public DateTime LastReload { get; private set; }
	public bool Debug { get; private set; }
	public int TokenExpiration { get; private set; }
	public Dictionary<string, APS> Data { get; set; } = [];
	public bool GetCfg(string input, [MaybeNullWhen(false)] out APS result) {
		if(NextReload<DateTime.UtcNow) Reload();
		return Data.TryGetValue(input, out result);
	} 

	private DateTime TokenCleanup { get; set; }
	private ConcurrentDictionary<Guid, TokenResponse> TokenCache { get; set; } = [];
	public bool GetToken(Guid token, [MaybeNullWhen(false)] out TokenResponse result){
		var now = DateTime.UtcNow;
		if(TokenCleanup < now){
			TokenCleanup = now.AddSeconds(int.TryParse(App.Configuration["TokenCleanup"],out var cln) ? cln : 3600);
			var del = new List<Guid>();
			foreach(var i in TokenCache) if(i.Value.ExpiresOn<now) del.Add(i.Key);
			foreach(var i in del) TokenCache.TryRemove(i, out _);
		}
		return TokenCache.TryRemove(token, out result);
	}
	public TokenResponse SetToken(APS cfg, AuthenticationResponse rsp, Guid? token=null){ 
		var tkn = token??Guid.NewGuid();
		var ret = new TokenResponse(){
			Token = tkn, AuthUrl = (cfg.Cfg?.TicketUrl??"")+rsp.Ticket, Ticket=rsp.Ticket,
			ExpiresIn = TokenExpiration, ExpiresOn = DateTime.UtcNow.AddSeconds(TokenExpiration)
		};
		return TokenCache[tkn]=ret;
	}

	public void Reload(){
		var cfg = App.Configuration;
		NextReload = DateTime.UtcNow.AddSeconds(int.TryParse(cfg["CfgReload"], out var rld)?rld:300);
		var crt = new Certs(); cfg.GetSection("Certificates").Bind(crt);
		var cfx = new Configs(); cfg.GetSection("Configurations").Bind(cfx);
		var apc = new Apps(); cfg.GetSection("Applications").Bind(apc);
		var postUrl = cfg["PostUrl"];
		var ticketUrl = cfg["TicketUrl"];

		Debug = bool.TryParse(cfg["Debug"], out var dbg) && dbg;
		if (Debug && !Directory.Exists("debug")) Directory.CreateDirectory("debug");

		TokenExpiration = int.TryParse(cfg["TokenExpiration"], out var tkx) ? tkx : 300;
		ConnStr = cfg["ConnStr"] ?? "";

		var data = new Dictionary<string, APS>();

		foreach (var i in apc){
			var j = i.Value;
			if(j.Secret is not null){
				var m = new ConfigItem() {
					Cert = crt.Get(i.Value.Cert??"Default"),
					BaseRequest = cfx.Get(i.Value.Config??"Default"),
				};
				m.PostUrl = i.Value.PostUrl ?? postUrl ?? m.PostUrl;
				m.TicketUrl = i.Value.TicketUrl ?? ticketUrl ?? m.TicketUrl;
				m.Pid = i.Value.Pid ?? m.BaseRequest.Pid;
				m.PostbackUrl = i.Value.PostbackUrl ?? m.BaseRequest.PostbackUrl;

				data[j.Secret] = new(){ Secret=j.Secret, Name=i.Key, Cfg = new (m), AllowV1=j.AllowV1, ShowAk=j.ShowAk, GetUser=j.GetUser };
			}
		}
		Data=data;
		LastReload = DateTime.UtcNow;
	}

	public Configuration(WebApplication app){ App=app; Reload(); ConnStr = app.Configuration["ConnStr"]??""; }
}




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


public static class RouteBuilders {
	public static RouteHandlerBuilder GetTokenV2(this RouteHandlerBuilder builder, Configuration cfg) => builder.AddEndpointFilter(async (flt, next) => {
		var ctx = flt.HttpContext;
		if(ctx.Request.Path.StartsWithSegments("/auth/v2", out var pth) && pth.HasValue) {
			var key = pth.Value.Split("/")[1];
			if (!string.IsNullOrWhiteSpace(key) && cfg.GetCfg(key, out var i) && i.Cfg is not null) {
				ctx.Items["Cfg"] = i;
				return await next(flt);
			}
			ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
		} else ctx.Response.StatusCode = StatusCodes.Status404NotFound;		
		return null;
	});

	public static bool GetCfg(this HttpContext ctx, [MaybeNullWhen(false)] out APS result) {
		if (ctx.Items["Cfg"] is APS aps) { result = aps; return true; }
		result = null; return false;
	}

}