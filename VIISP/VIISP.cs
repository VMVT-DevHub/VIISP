
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Serialization;
using System.Text.Json.Serialization;

namespace VIISP;


public class Config(ConfigItem cfg) {
	private static readonly XmlSerializerNamespaces NS = new([new XmlQualifiedName("auth", "http://www.epaslaugos.lt/services/authentication")]);
	private ConfigItem Cfg { get; } = cfg;
	private Cert Cert { get; } = new(cfg.Cert?.Cert ?? "", cfg.Cert?.Pass ?? "");
	public string PostUrl => Cfg.PostUrl;
	public string TicketUrl => Cfg.TicketUrl;
	public string? PostbackUrl => Cfg.PostbackUrl;
	public string? Pid => Cfg.Pid;
	public AuthenticationRequest? BaseRequest => Cfg.BaseRequest;
	public XmlDocument SignXml<T>(T req) where T : Request {
		var doc = new XmlDocument();
		using var ms = new MemoryStream();
		new XmlSerializer(typeof(T)).Serialize(ms, req, NS);
		ms.Position = 0; doc.Load(ms);
		Cert.Sign(doc); return doc;
	}
}

public class CertItem {
	public string? Name { get; set; }
	public string? Cert { get; set; }
	public string? Pass { get; set; }
}

public class ConfigItem {
	public CertItem? Cert { get; set; }
	public string? PostbackUrl { get; set; }
	public string? Pid { get; set; }
	public string PostUrl { get; set; } = "https://www.epaslaugos.lt/portal/authenticationServices/auth";
	public string TicketUrl { get; set; } = "https://www.epaslaugos.lt/portal/external/services/authentication/v2/?ticket=";
	public AuthenticationRequest? BaseRequest { get; set; }
}


public class Cert {
	private string DigestMethod { get; set; } = "http://www.w3.org/2000/09/xmldsig#sha1";
	private string CanonicalizationMethod { get; set; } = "http://www.w3.org/2001/10/xml-exc-c14n#";
	private string ReferenceUrl { get; set; } = "#uniqueNodeId";
	private KeyInfo PublicKey { get; } = new KeyInfo();
	private AsymmetricAlgorithm? PrivateKey { get; }
	public Cert(string cert, string pass){
		var crt = new X509Certificate2(Convert.FromBase64String(cert), pass);
		PrivateKey = crt.GetRSAPrivateKey();
		var pub = crt.GetRSAPublicKey();
		if(pub is not null) PublicKey.AddClause(new RSAKeyValue(pub));
	}

	public void Sign(XmlDocument doc){
		if(doc.DocumentElement is not null){
			var sign = new SignedXml(doc);
			if(sign.SignedInfo is not null) sign.SignedInfo.CanonicalizationMethod = CanonicalizationMethod;
			var rfr = new Reference(ReferenceUrl) { DigestMethod = DigestMethod };
			rfr.AddTransform(new XmlDsigEnvelopedSignatureTransform());
			rfr.AddTransform(new XmlDsigExcC14NTransform { Algorithm = CanonicalizationMethod });
			sign.AddReference(rfr); 
			sign.KeyInfo = PublicKey;
			sign.SigningKey = PrivateKey;
			sign.ComputeSignature();
			doc.DocumentElement.AppendChild(sign.GetXml());
		}
	}
}


public class Request {
	private static readonly HttpClient HClient = new();

	//Todo: prevent DDOS

	public static async Task<To> Execute<Ti, To>(Ti req, Config cfg, CancellationToken ct) where Ti : Request where To : Response, new() {
		var rsp = await HClient.PostAsync(cfg.PostUrl, new StringContent(CreateSoapEnvelope(cfg.SignXml(req)).OuterXml, System.Text.Encoding.UTF8, "application/xml"), ct);
		using var stream = await rsp.Content.ReadAsStreamAsync(ct);
		using var reader = XmlReader.Create(stream);
		var rspd = new XmlSerializer(typeof(SoapEnvelope)).Deserialize(reader);
		if(rspd is SoapEnvelope rspo){
			if(rspo.Body is not null) {
				if (rsp.IsSuccessStatusCode) {
					var prps = rspo.Body.GetType().GetProperties(); var p1=typeof(To);
					foreach(var p in prps) if(p.PropertyType == p1 && p.GetValue(rspo.Body) is To to) return to;
				}
				else if(rspo.Body.Fault is not null) return new To(){ Error=rspo.Body.Fault };
				return new To(){ Error=new(){ Code="soap:Error", Message="Response type not found" } };
			}
			return new To(){ Error=new(){ Code="soap:Empty", Message="Missing response body" } };
		}
		return new To(){ Error=new(){ Code="soap:Format", Message="Invalid response format" } };
	}


	private static XmlElement Element(XmlDocument doc, string name) => doc.CreateElement("soapenv", name, "http://schemas.xmlsoap.org/soap/envelope/");
	private static XmlDocument CreateSoapEnvelope(XmlDocument body) {
		if(body.DocumentElement is null) return body;
		var doc = new XmlDocument();
		var evl = Element(doc, "Envelope");
		var bdy = Element(doc, "Body");
		doc.AppendChild(evl);
		evl.AppendChild(Element(doc, "Header"));
		bdy.AppendChild(doc.ImportNode(body.DocumentElement, true));
		evl.AppendChild(bdy);
		return doc;
	}

	public static string FCase(string? text){
		if (string.IsNullOrEmpty(text)) return string.Empty;
		var words = text.ToLower().Replace(",",", ").Replace("  "," ").Split(' ');
		return string.Join(" ", words.Select(word => word.Length > 0 ? char.ToUpper(word[0]) + word[1..] : word));
	}
}


[XmlRoot("authenticationRequest", Namespace = "http://www.epaslaugos.lt/services/authentication")]
public class AuthenticationRequest : Request {
	[XmlAttribute("id")] public string? UniqueNodeId { get; set; } = "uniqueNodeId";
	[XmlElement("pid")] public string? Pid { get; set; }
	[XmlElement("serviceTarget")] public List<string>? ServiceTarget { get; set; } //= ["citizen","business","provider"];
	[XmlElement("authenticationProvider")] public List<string>? AuthenticationProviders { get; set; } = ["auth.lt.identity.card","auth.lt.government.employee.card","auth.lt.bank","auth.eidas","auth.signatureProvider","auth.iltu.identity.card"];
	[XmlElement("authenticationAttribute")] public List<string>? AuthenticationAttributes { get; set; } = ["lt-personal-code","lt-company-code","lt-government-employee-code","eidas-eid","iltu-personal-code"];
	[XmlElement("userInformation")] public List<string>? UserInformation { get; set; } = ["id","firstName","lastName","address","email","phoneNumber","birthday","companyName","nationality","proxyType","proxySource"];
	[XmlElement("proxyAuthenticationAttribute")] public List<string>? ProxyAuthenticationAttribute { get; set; } = ["lt-personal-code","lt-company-code","lt-government-employee-code","eidas-eid","iltu-personal-code"];
	[XmlElement("proxyUserInformation")] public List<string>? ProxyUserInformation { get; set; } = ["id","firstName","lastName","address","email","phoneNumber","birthday","companyName","nationality","proxyType","proxySource"];
	[XmlElement("postbackUrl")] public string? PostbackUrl { get; set; }
	[XmlElement("customData")] public string? CustomData { get; set; }
	public async Task<AuthenticationResponse> Execute(Config cfg, CancellationToken ct) {
		foreach (var prp in typeof(AuthenticationRequest).GetProperties()) {
			var vl = prp.GetValue(cfg.BaseRequest); if(vl is not null) prp.SetValue(this,vl);
		}
		return await Execute<AuthenticationRequest, AuthenticationResponse>(this, cfg, ct);
	}
}


[XmlRoot("authenticationDataRequest", Namespace = "http://www.epaslaugos.lt/services/authentication")]
public class AuthenticationDataRequest : Request {
	[XmlAttribute("id")] public string? UniqueNodeId { get; set; } = "uniqueNodeId";
	[XmlElement("pid")] public string? Pid { get; set; }
	[XmlElement("ticket")] public Guid? Ticket { get; set; }
	[XmlElement("includeSourceData")] public bool IncludeSourceData { get; set; } = true;
	public async Task<AuthenticationDataResponse> Execute(Config cfg, CancellationToken ct) {
		Pid??=cfg.Pid;
		return await Execute<AuthenticationDataRequest, AuthenticationDataResponse>(this, cfg, ct);
	}
	public AuthenticationDataRequest(){}
	public AuthenticationDataRequest(Guid? ticket){ Ticket=ticket; }
	public AuthenticationDataRequest(string? ticket){ Ticket=Guid.TryParse(ticket, out var tkt)?tkt:null; }
}



[XmlRoot("Envelope", Namespace = "http://schemas.xmlsoap.org/soap/envelope/")] 
public class SoapEnvelope { [XmlElement("Header")] public SoapHeader? Header { get; set; } [XmlElement("Body")] public SoapBody? Body { get; set; } }
public class SoapHeader { }
public class SoapFault {
	[XmlIgnore] public bool Error { get; set; } = true;
	[XmlElement("faultcode", Namespace = "")] public string? Code { get; set; }
	[XmlElement("faultstring", Namespace = "")] public string? Message { get; set; }
}
public class SoapBody {
	[XmlElement("authenticationResponse", Namespace = "http://www.epaslaugos.lt/services/authentication")] public AuthenticationResponse? AuthenticationResponse { get; set; }
	[XmlElement("authenticationDataResponse", Namespace = "http://www.epaslaugos.lt/services/authentication")] public AuthenticationDataResponse? AuthenticationDataResponse { get; set; }
	[XmlElement("Fault")] public SoapFault? Fault { get; set; }
}

public class Response  {
	public SoapFault? Error { get; set; }
}
public class AuthenticationResponse : Response {
	[XmlAttribute("id")] public string? Id { get; set; }
	[XmlElement("ticket")] public Guid? Ticket { get; set; }
}
public class AuthenticationDataResponse : Response {
	[XmlAttribute("id")] public string? Id { get; set; }
	[XmlElement("ticket")] public string? Ticket { get; set; }
	[XmlElement("authenticationProvider")] public string? AuthenticationProvider { get; set; }
	[XmlElement("userInformation")]public List<AuthRspUserInfo>? UserInformation { get; set; }
	[XmlElement("sourceData")] public AuthRspSourceData? SourceData { get; set; }
	[XmlElement("authenticationAttribute")] public List<AuthRspAuthAttr>? AuthAttr { get; set; }
}

public class AuthRspSourceData { [XmlElement("type")] public string? Type { get; set; } [XmlElement("parameter")] public List<AuthRspSourceDataParams>? Params { get; set; } }
public class AuthRspSourceDataParams { [XmlAttribute("name")] public string? Name { get; set; } [XmlText] public string? Value { get; set; } }
public class AuthRspUserInfo { [XmlElement("information")] public string? Name { get; set; } [XmlElement("value")] public AuthRspUserInfoVal? Value { get; set; } }
public class AuthRspAuthAttr { [XmlElement("attribute")] public string? Name { get; set; } [XmlElement("value")] public string? Value { get; set; } }
public class AuthRspUserInfoVal { [XmlElement("stringValue")] public string? StringValue { get; set; } [XmlElement("dateValue")] public DateTime? DateValue { get; set; } }




/// <summary>Vartotojo informacija</summary>
public class DataResponse {
	[JsonPropertyName("id")] public Guid? Id { get; set; }
	[JsonPropertyName("name")] public string? Name { get; set; }
	[JsonPropertyName("firstName")] public string? FName { get; set; }
	[JsonPropertyName("lastName")] public string? LName { get; set; }
	[JsonPropertyName("email")] public string? Email { get; set; }
	[JsonPropertyName("address")] public string? Address { get; set; }
	[JsonPropertyName("phoneNumber")] public string? Phone { get; set; }
	[JsonPropertyName("birthday")] public DateTime? Birthday { get; set; }
	[JsonPropertyName("lt-personal-code")] public string? AK { get; set; }
	[JsonPropertyName("lt-company-code")] public string? CompanyCode { get; set; }
	[JsonPropertyName("companyName")] public string? CompanyName { get; set; }
	[JsonPropertyName("country")] public string? Country { get; set; }
	[JsonPropertyName("sndId")] public string? SndId { get; set; }
	[JsonPropertyName("recId")] public string? RecId { get; set; }
	[JsonPropertyName("service")] public string? Service { get; set; }
	[JsonPropertyName("language")] public string? Language { get; set; }
	[JsonPropertyName("provider")] public string? Provider { get; set; }
	[JsonPropertyName("proxyType")] public string? ProxyType { get; set; }
	[JsonPropertyName("proxySource")] public string? ProxySource { get; set; }

	public DataResponse(AuthenticationDataResponse itm){
		Provider = itm.AuthenticationProvider;
		if(itm.UserInformation is not null)
		foreach(var i in itm.UserInformation){
			if(i.Value is not null)
			switch(i.Name){
				case "firstName": FName = Request.FCase(i.Value?.StringValue); break;
				case "lastName": LName = Request.FCase(i.Value?.StringValue); break;
				case "address": Address = i.Value.StringValue; break;
				case "email": Email = i.Value.StringValue; break;
				case "phoneNumber": Phone = i.Value.StringValue; break;
				case "birthday": Birthday = i.Value.DateValue; break;
				case "companyName": CompanyName = i.Value.StringValue; break;
				case "proxyType": ProxyType = i.Value.StringValue; break;
				case "proxySource": ProxySource = i.Value.StringValue; break;
			}
		}
		if(itm.AuthAttr is not null)
		foreach(var i in itm.AuthAttr){
			switch (i.Name) {
				case "lt-company-code": CompanyCode = i.Value; break;
				case "lt-personal-code": AK = i.Value; break;
			}
		}

		if(itm.SourceData?.Params is not null)
		foreach(var i in itm.SourceData.Params){
			switch (i.Name){
				case "VK_USER_NAME": Name=Request.FCase(i.Value); break;
				case "VK_COUNTRY": Country=i.Value; break;
				case "VK_SND_ID": SndId=i.Value; break;
				case "VK_REC_ID": RecId=i.Value; break;
				case "VK_LANG": Language=i.Value; break;
				case "VK_USER_ID": AK = i.Value; break;
				case "VK_SERVICE": Service = i.Value; break;
				case "CN": Service = i.Value; break;
				case "O": SndId = i.Value; break;
			}
		}

	}
}