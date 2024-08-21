using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;

namespace VIISP.App;

public class Configuration {
	private WebApplication App { get; }
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
		TokenExpiration = int.TryParse(cfg["TokenExpiration"], out var tkx) ? tkx : 300;

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
				m.BaseRequest.Pid = i.Value.Pid;
				m.PostbackUrl = i.Value.PostbackUrl ??= m.BaseRequest.PostbackUrl ?? "";

				data[j.Secret] = new(){ Secret=j.Secret, Name=i.Key, Cfg = new (m), AllowV1=j.AllowV1 };
			}
		}
		Data=data;
		LastReload = DateTime.UtcNow;
	}

	public Configuration(WebApplication app){ App=app; Reload(); }
}