
using System.Text.Json.Serialization;

namespace VIISP.App;

public class Certs : Dictionary<string, CertItem> {
	public CertItem Get(string name) => TryGetValue(name, out var crt) ? crt : new();
}
public class Configs : Dictionary<string, AuthenticationRequest> {
	public AuthenticationRequest Get(string name) => TryGetValue(name, out var cfg) ? cfg : new();
}

public class Apps : Dictionary<string, App> {
	public App Get(string name) => TryGetValue(name, out var app) ? app : new();
}



public class App {
	public string? Name { get; set; }
	public string? Secret { get; set; }
	public string? Cert { get; set; }
	public string? Config { get; set; }
	public string? Pid { get; set; }
	public string? PostbackUrl { get; set; }
	public string? PostUrl { get; set; }
	public string? TicketUrl { get; set; }
	public bool AllowV1 { get; set; }
	public bool ShowAk { get; set; }
	public bool GetUser { get; set; }

}

public class APS {
	public string? Name { get; set; }
	public string? Secret { get; set; }
	public Config? Cfg { get; set; }
	public bool AllowV1 { get; set; }
	public bool ShowAk { get; set; }
	public bool GetUser { get; set; }
}

public class TicketResponse_v1 {
	public Guid? Ticket { get; set; }
	public string? Host { get; set; }
	public string? Url { get; set; }
}


public class TokenResponse {
	[JsonIgnore] public Guid? Ticket { get; set; }
	public Guid? Token { get; set; }
	public int ExpiresIn { get; set;}
	public DateTime ExpiresOn { get; set; }
	public string? AuthUrl { get; set; }
}

public class UserData {
	[JsonPropertyName("id")] public Guid? Id { get; set; }
	[JsonPropertyName("ak")] public long? AK { get; set; }
	[JsonPropertyName("name")] public string? Name { get; set; }
	[JsonPropertyName("firstName")] public string? FName { get; set; }
	[JsonPropertyName("lastName")] public string? LName { get; set; }
	[JsonPropertyName("email")] public string? Email { get; set; }
	[JsonPropertyName("address")] public string? Address { get; set; }
	[JsonPropertyName("phoneNumber")] public string? Phone { get; set; }
	[JsonPropertyName("country")] public string? Country { get; set; }
	[JsonPropertyName("real")] public bool Real { get; set; } = false;
}
