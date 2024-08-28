

using Microsoft.AspNetCore.Mvc.Formatters;
using Npgsql;
using Npgsql.Replication.PgOutput.Messages;
using System.Diagnostics.Eventing.Reader;
using System.Diagnostics.Metrics;
using System.Net;
using System.Numerics;
using System.Text.Json;
using System.Xml.Linq;

namespace VIISP.App;

public static class DBExec {

	public static T Login<T>(this T dt, string connstr, string? app, bool showAk = false) where T : DataResponse {
		using var conn = new NpgsqlConnection(connstr); conn.Open();
		if (dt.AK > 1e10 && dt.AK < 1e11) {
			using var cmd = new NpgsqlCommand("SELECT id,name,fname,lname,address,email,phone FROM viisp.user_login(@ak,@app,null,null,@data::jsonb)", conn);
			cmd.Parameters.Add(new("@ak", dt.AK));
			cmd.Parameters.Add(new("@app", app));
			var m = dt.GetType();
			cmd.Parameters.Add(new("@data", JsonSerializer.Serialize(dt)));

			using var reader = cmd.ExecuteReader();

			if (!showAk) dt.AK = null;
			if (reader.Read()) {
				dt.Id = reader.IsDBNull(0) ? null : reader.GetGuid(0);
			}
			else { } //TODO: log error
		}
		else { } //TODO: log error
		return dt;
	}


	private static readonly string GetUserSql = "SELECT user_id, user_ak, user_name, user_fname, user_lname, user_address, user_email, user_phone, user_country, user_real FROM viisp.users";
	private static readonly string CreateUserSql = "INSERT INTO viisp.users (user_ak,user_name,user_fname,user_lname,user_address,user_email,user_phone,user_country) VALUES (@ak,@name,@fname,@lname,@address,@email,@phone,@country)";
	private static readonly string SetUserSql = "UPDATE viisp.users SET user_name=@name,user_fname=@fname,user_lname=@lname,user_address=@address,user_email=@email,user_phone=@phone,user_country=@country ";


	private static UserData GetUser(NpgsqlDataReader rdr, bool showAk = false) => new() {
		Id = rdr.IsDBNull(0) ? null : rdr.GetGuid(0),
		AK = !showAk || rdr.IsDBNull(1) ? null : rdr.GetInt64(1),
		Name = rdr.IsDBNull(2) ? null : rdr.GetString(2),
		FName = rdr.IsDBNull(3) ? null : rdr.GetString(3),
		LName = rdr.IsDBNull(4) ? null : rdr.GetString(4),
		Address = rdr.IsDBNull(5) ? null : rdr.GetString(5),
		Email = rdr.IsDBNull(6) ? null : rdr.GetString(6),
		Phone = rdr.IsDBNull(7) ? null : rdr.GetString(7),
		Country = rdr.IsDBNull(8) ? null : rdr.GetString(8),
		Real = !rdr.IsDBNull(9) && rdr.GetBoolean(9)
	};
	private static UserData? GetUserAk(NpgsqlConnection conn, long ak, bool showAk=false) {
		using var cmd = new NpgsqlCommand($"{GetUserSql} WHERE user_ak={ak}", conn);
		using var rdr = cmd.ExecuteReader();
		return rdr.Read() ? GetUser(rdr, showAk) : null;
	}
	private static NpgsqlCommand SetParams(this NpgsqlCommand cmd, UserData usr, UserData? curr=null) {
		cmd.Parameters.Add(new("@ak", usr.AK ?? curr?.AK));
		cmd.Parameters.Add(new("@name", usr.Name ?? curr?.Name));
		cmd.Parameters.Add(new("@fname", usr.FName ?? curr?.FName));
		cmd.Parameters.Add(new("@lname", usr.LName ?? curr?.LName));
		cmd.Parameters.Add(new("@address", usr.Address ?? curr?.Address ?? (object)DBNull.Value));
		cmd.Parameters.Add(new("@email", usr.Email ?? curr?.Email ?? (object)DBNull.Value));
		cmd.Parameters.Add(new("@phone", usr.Phone ?? curr?.Phone ?? (object)DBNull.Value));
		cmd.Parameters.Add(new("@country", usr.Country ?? curr?.Country ?? (object)DBNull.Value));
		return cmd;
	}

	public static UserData? GetUser(this Guid user, string connstr, string? app, bool showAk = false) => GetUser("user_id", user, connstr, app, showAk);
	public static UserData? GetUser(this long user, string connstr, string? app, bool showAk = false) => GetUser("user_ak", user, connstr, app, showAk);
	private static UserData? GetUser(string where, object user, string connstr, string? app, bool showAk = false) {
		using var conn = new NpgsqlConnection(connstr); conn.Open();
		using var cmd = new NpgsqlCommand($"{GetUserSql} WHERE {where}='{user}'", conn);
		using var reader = cmd.ExecuteReader();
		if (reader.Read()) return GetUser(reader, showAk);
		else { } //TODO: log error
		return null;
	}

	public static UserData CreateUser(this UserData usr, string connstr, string? app, bool showAk = false) {
		if (usr.AK > 1e10 && usr.AK < 1e11) {
			if (string.IsNullOrWhiteSpace(usr.LName) || string.IsNullOrWhiteSpace(usr.FName)) return usr; //TODO: log error
			if (string.IsNullOrWhiteSpace(usr.Name)) usr.Name = $"{usr.LName}, {usr.FName}";

			using var conn = new NpgsqlConnection(connstr); conn.Open();

			var curr = GetUserAk(conn, usr.AK??0, showAk);
			if (curr?.Id is not null) {
				if (curr.Real) return curr;
				usr.Id = curr.Id;
				if ((usr.Name ?? "") != (curr.Name ?? "") || (usr.FName ?? "") != (curr.FName ?? "") || (usr.LName ?? "") != (curr.LName ?? "") ||
						(usr.Address is not null && (usr.Address ?? "") != (curr.Address ?? "")) || (usr.Email is not null && (usr.Email ?? "") != (curr.Email ?? "")) ||
						(usr.Phone is not null && (usr.Phone ?? "") != (curr.Phone ?? "")) || (usr.Country is not null && (usr.Country ?? "") != (curr.Country ?? ""))) {
					using var cmd = new NpgsqlCommand($"{SetUserSql} WHERE user_ak={usr.AK}", conn); cmd.SetParams(usr, curr).ExecuteNonQuery();
				}
			}
			else {
				using var cmd = new NpgsqlCommand(CreateUserSql, conn); cmd.SetParams(usr); cmd.ExecuteNonQuery();
			}
			var ret = GetUserAk(conn, usr.AK ?? 0, showAk);
			if (ret?.Id is not null) return ret;
			else { } //TODO: log error
		}
		else { } //TODO: log error
		return usr;
	}
}